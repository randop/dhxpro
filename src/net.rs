//! io_uring DHCP transport.
//!
//! All DHCP receive and send operations go through `io_uring`
//! (`IORING_OP_RECVMSG` / `IORING_OP_SENDMSG`). There is no
//! `std::net::UdpSocket`, blocking `recvfrom`/`sendto` loop or epoll backend.
//!
//! The socket is bound to `0.0.0.0:67`; subnet selection uses the
//! `IP_PKTINFO` ancillary data captured by `recvmsg`. Replies carry an
//! `IP_PKTINFO` control message so the kernel uses the intended source address
//! and outgoing interface.

use std::collections::HashMap;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use io_uring::types::{Fd, Timespec};
use io_uring::{opcode, IoUring, Probe};

use crate::error::{Error, Result};
use crate::server::{DhcpServer, Ingress, Outbound, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};

const USER_DATA_RECV: u64 = 1;
const USER_DATA_TIMER: u64 = 2;
const USER_DATA_TX_BASE: u64 = 16;
const USER_DATA_CANCEL_BASE: u64 = 1 << 63;
const TX_INFLIGHT_LIMIT: usize = 32;
const RX_BUFFER_LEN: usize = 4096;
const TIMER_INTERVAL_SECONDS: u64 = 1;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_shutdown_signal(_signal: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install SIGINT/SIGTERM handlers that merely set a flag. The event loop
/// notices it on the next timer completion (at most one second).
pub fn install_signal_handlers() -> Result<()> {
    unsafe {
        let mut action: libc::sigaction = zeroed();
        action.sa_sigaction = on_shutdown_signal as *const () as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(Error::Io(io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Map io_uring setup/submit errors to an actionable startup diagnostic.
fn ring_startup_error(context: &str, error: io::Error) -> Error {
    let hint = match error.raw_os_error() {
        Some(libc::ENOSYS) => " (the kernel does not implement io_uring; enable CONFIG_IO_URING)",
        Some(libc::EPERM) | Some(libc::EACCES) => {
            " (io_uring is blocked by seccomp/permissions; check the container or firmware policy)"
        }
        Some(libc::ENOMEM) => " (not enough memory for the io_uring rings)",
        Some(libc::EMFILE) | Some(libc::ENFILE) => " (file descriptor limit reached)",
        _ => "",
    };
    Error::IoUringUnavailable(format!("{context}: {error}{hint}"))
}

/// Verify that the kernel supports the opcodes dhxpro needs.
fn probe_required_operations(ring: &IoUring) -> Result<()> {
    let mut probe = Probe::new();
    ring.submitter()
        .register_probe(&mut probe)
        .map_err(|error| ring_startup_error("IORING_REGISTER_PROBE failed", error))?;
    for (name, code) in [
        ("IORING_OP_RECVMSG", opcode::RecvMsg::CODE),
        ("IORING_OP_SENDMSG", opcode::SendMsg::CODE),
        ("IORING_OP_TIMEOUT", opcode::Timeout::CODE),
        ("IORING_OP_ASYNC_CANCEL", opcode::AsyncCancel::CODE),
    ] {
        if !probe.is_supported(code) {
            return Err(Error::IoUringUnavailable(format!(
                "kernel io_uring implementation lacks {name}"
            )));
        }
    }
    Ok(())
}

fn create_udp_socket(bind_port: u16) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let setup = (|| -> io::Result<()> {
        // Deliberately do not set SO_REUSEADDR: a second DHCP listener on the
        // same port must fail the bind instead of splitting client traffic.
        set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1)?;
        set_sockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
        set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 256 * 1024)?;
        bind_udp(fd, Ipv4Addr::UNSPECIFIED, bind_port)
    })();

    if let Err(error) = setup {
        unsafe { libc::close(fd) };
        return Err(Error::net(format!(
            "failed to configure UDP socket port {bind_port}: {error}"
        )));
    }
    Ok(fd)
}

fn set_sockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind_udp(fd: RawFd, address: Ipv4Addr, port: u16) -> io::Result<()> {
    let addr = sockaddr_in(address, port);
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sockaddr_in(address: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(address).to_be(),
        },
        sin_zero: [0; 8],
    }
}

fn socket_port(fd: RawFd) -> io::Result<u16> {
    let mut addr: libc::sockaddr_in = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe { libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u16::from_be(addr.sin_port))
}

fn interface_name(ifindex: u32) -> Option<String> {
    if ifindex == 0 {
        return None;
    }
    let mut buffer = [0u8; libc::IF_NAMESIZE + 1];
    let rc = unsafe { libc::if_indextoname(ifindex, buffer.as_mut_ptr() as *mut libc::c_char) };
    if rc.is_null() {
        return None;
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    std::str::from_utf8(&buffer[..end]).ok().map(str::to_string)
}

/// Stable receive buffers. Their addresses are handed to the kernel, so they
/// are boxed and never moved while an operation is in flight.
struct ReceiveBuffers {
    data: Box<[u8; RX_BUFFER_LEN]>,
    /// Word-aligned storage for `cmsghdr`/`in_pktinfo`; a byte array would
    /// only guarantee alignment 1 even though the allocator is usually more
    /// generous.
    control: Box<[u64; 32]>,
    name: Box<libc::sockaddr_storage>,
    iov: Box<libc::iovec>,
    msghdr: Box<libc::msghdr>,
}

impl ReceiveBuffers {
    fn new() -> Self {
        Self {
            data: Box::new([0u8; RX_BUFFER_LEN]),
            control: Box::new([0u64; 32]),
            name: Box::new(unsafe { zeroed() }),
            iov: Box::new(libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }),
            msghdr: Box::new(unsafe { zeroed() }),
        }
    }

    fn prepare(&mut self) {
        self.control.fill(0);
        *self.name = unsafe { zeroed() };
        self.iov.iov_base = self.data.as_mut_ptr() as *mut libc::c_void;
        self.iov.iov_len = RX_BUFFER_LEN;
        let msghdr = &mut *self.msghdr;
        msghdr.msg_name = &mut *self.name as *mut libc::sockaddr_storage as *mut libc::c_void;
        msghdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msghdr.msg_iov = self.iov.as_mut() as *mut libc::iovec;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = self.control.as_mut_ptr() as *mut libc::c_void;
        msghdr.msg_controllen = std::mem::size_of_val(&*self.control) as _;
        msghdr.msg_flags = 0;
    }
}

/// One send operation whose buffers must outlive the submission. The buffer
/// fields are not read after construction; they own the memory referenced by
/// the msghdr until the completion arrives.
#[allow(dead_code)]
struct SendOp {
    payload: Box<[u8]>,
    name: Box<libc::sockaddr_in>,
    iov: Box<libc::iovec>,
    control: Box<[usize]>,
    msghdr: Box<libc::msghdr>,
}

impl SendOp {
    fn new(outbound: &Outbound) -> Self {
        let (destination, port, ifindex, source, payload) = match outbound {
            Outbound::Direct {
                destination,
                ifindex,
                source,
                payload,
            } => (
                *destination,
                DHCP_CLIENT_PORT,
                *ifindex,
                Some(*source),
                payload,
            ),
            Outbound::Relay {
                destination,
                payload,
            } => (*destination, DHCP_SERVER_PORT, 0, None, payload),
        };

        let payload: Box<[u8]> = payload.clone().into_boxed_slice();
        let name = Box::new(sockaddr_in(destination, port));
        let mut iov = Box::new(libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        });
        iov.iov_base = payload.as_ptr() as *mut libc::c_void;

        let pktinfo_size = size_of::<libc::in_pktinfo>();
        let control_len = unsafe { libc::CMSG_SPACE(pktinfo_size as libc::c_uint) as usize };
        let control_words = control_len.div_ceil(size_of::<usize>());
        let mut control: Box<[usize]> = vec![0usize; control_words].into_boxed_slice();
        let mut msg_control = std::ptr::null_mut();
        let mut msg_controllen = 0;

        if let Some(source) = source {
            unsafe {
                let cmsg = control.as_mut_ptr() as *mut libc::cmsghdr;
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(pktinfo_size as libc::c_uint) as _;
                let info = libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo;
                (*info).ipi_ifindex = ifindex as libc::c_int;
                (*info).ipi_spec_dst = libc::in_addr {
                    s_addr: u32::from(source).to_be(),
                };
                (*info).ipi_addr = libc::in_addr { s_addr: 0 };
            }
            msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg_controllen = control_len as _;
        }
        let msghdr = Box::new(libc::msghdr {
            msg_name: name.as_ref() as *const _ as *mut libc::c_void,
            msg_namelen: size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: iov.as_mut() as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control,
            msg_controllen,
            msg_flags: 0,
        });

        Self {
            payload,
            name,
            iov,
            control,
            msghdr,
        }
    }

    fn len(&self) -> usize {
        self.payload.len()
    }
}

pub struct UdpDhcpSocket {
    fd: RawFd,
    ring: IoUring,
    rx: ReceiveBuffers,
    tx: HashMap<u64, SendOp>,
    next_tx_id: u64,
    timer: Box<Timespec>,
    recv_armed: bool,
    timer_armed: bool,
}

impl UdpDhcpSocket {
    /// Bind the DHCP server socket and prepare the io_uring instance. Fails
    /// with a clear diagnostic when io_uring or a required opcode is
    /// unavailable; there is no fallback backend.
    pub fn bind_dhcp() -> Result<Self> {
        Self::bind(DHCP_SERVER_PORT)
    }

    fn bind(port: u16) -> Result<Self> {
        let ring = IoUring::new(64)
            .map_err(|error| ring_startup_error("failed to create io_uring instance", error))?;
        probe_required_operations(&ring)?;
        let fd = create_udp_socket(port)?;
        Ok(Self {
            fd,
            ring,
            rx: ReceiveBuffers::new(),
            tx: HashMap::new(),
            next_tx_id: USER_DATA_TX_BASE,
            timer: Box::new(Timespec::new()),
            recv_armed: false,
            timer_armed: false,
        })
    }

    pub fn local_port(&self) -> Result<u16> {
        socket_port(self.fd).map_err(Error::Io)
    }

    /// Completion-driven event loop. All receives, sends, timers and
    /// cancellations are io_uring operations.
    pub fn run(&mut self, server: &mut DhcpServer) -> Result<()> {
        let result = self.run_loop(server);
        self.cancel_and_drain();
        result
    }

    fn run_loop(&mut self, server: &mut DhcpServer) -> Result<()> {
        eprintln!(
            "dhxpro: serving DHCP on UDP port {} via io_uring",
            self.local_port()?
        );
        self.arm_timer()?;
        self.arm_receive()?;

        loop {
            if shutdown_requested() {
                eprintln!("dhxpro: shutdown signal received, draining io_uring operations");
                break;
            }

            match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(Error::net(format!(
                        "io_uring submit_and_wait failed: {error}"
                    )))
                }
            }

            let mut completions = Vec::new();
            {
                let mut completion = self.ring.completion();
                completion.sync();
                for cqe in &mut completion {
                    completions.push((cqe.user_data(), cqe.result(), cqe.flags()));
                }
            }

            for (user_data, result, _flags) in completions {
                match user_data {
                    USER_DATA_RECV => {
                        self.recv_armed = false;
                        self.handle_receive(result, server)?;
                    }
                    USER_DATA_TIMER => {
                        self.timer_armed = false;
                        if result == -libc::ETIME || result == 0 {
                            if let Err(error) = server.tick() {
                                eprintln!("dhxpro: periodic maintenance failed: {error}");
                            }
                        } else if result == -libc::ECANCELED {
                            // Shutdown in progress.
                        }
                    }
                    user_data => self.handle_send_completion(user_data, result),
                }
            }

            if !self.recv_armed && !shutdown_requested() && self.tx.len() < TX_INFLIGHT_LIMIT {
                self.arm_receive()?;
            }
            if !self.timer_armed && !shutdown_requested() {
                self.arm_timer()?;
            }
        }

        Ok(())
    }

    fn arm_receive(&mut self) -> Result<()> {
        self.rx.prepare();
        let entry = opcode::RecvMsg::new(Fd(self.fd), self.rx.msghdr.as_mut() as *mut _)
            .build()
            .user_data(USER_DATA_RECV);
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|error| Error::net(format!("io_uring submission queue full: {error}")))?;
        }
        self.recv_armed = true;
        Ok(())
    }

    fn arm_timer(&mut self) -> Result<()> {
        *self.timer = Timespec::new().sec(TIMER_INTERVAL_SECONDS);
        let entry = opcode::Timeout::new(self.timer.as_ref() as *const _)
            .build()
            .user_data(USER_DATA_TIMER);
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|error| Error::net(format!("io_uring submission queue full: {error}")))?;
        }
        self.timer_armed = true;
        Ok(())
    }

    fn handle_receive(&mut self, result: i32, server: &mut DhcpServer) -> Result<()> {
        if result < 0 {
            let error = io::Error::from_raw_os_error(-result);
            return match -result {
                libc::EAGAIN | libc::EINTR | libc::ENOBUFS | libc::ENOMEM => {
                    eprintln!("dhxpro: transient receive error: {error}");
                    Ok(())
                }
                libc::ECANCELED => Ok(()),
                _ => Err(Error::net(format!("DHCP receive failed: {error}"))),
            };
        }
        if result == 0 {
            return Ok(());
        }

        let length = result as usize;
        if length > RX_BUFFER_LEN {
            eprintln!("dhxpro: dropping oversized DHCP datagram ({length} bytes)");
            return Ok(());
        }
        if self.rx.msghdr.msg_flags & libc::MSG_TRUNC != 0 {
            eprintln!("dhxpro: dropping truncated DHCP datagram");
            return Ok(());
        }
        if self.rx.msghdr.msg_flags & libc::MSG_CTRUNC != 0 {
            eprintln!("dhxpro: dropping datagram with truncated ancillary data");
            return Ok(());
        }

        let Some((ingress, payload)) =
            parse_ingress(&self.rx.msghdr, &self.rx.data[..length], &self.rx.name)
        else {
            eprintln!("dhxpro: dropping datagram without usable IP_PKTINFO metadata");
            return Ok(());
        };

        let outbounds = server.handle_datagram(&payload, &ingress);
        for outbound in outbounds {
            self.submit_send(&outbound)?;
        }
        Ok(())
    }

    fn submit_send(&mut self, outbound: &Outbound) -> Result<()> {
        if self.tx.len() >= TX_INFLIGHT_LIMIT {
            eprintln!(
                "dhxpro: send queue full; dropping reply to {}",
                match outbound {
                    Outbound::Direct { destination, .. } => destination.to_string(),
                    Outbound::Relay { destination, .. } => destination.to_string(),
                }
            );
            return Ok(());
        }
        let id = self.next_tx_id;
        self.next_tx_id = self.next_tx_id.wrapping_add(1);
        let op = SendOp::new(outbound);
        let entry = opcode::SendMsg::new(Fd(self.fd), op.msghdr.as_ref() as *const _)
            .build()
            .user_data(id);
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|error| Error::net(format!("io_uring submission queue full: {error}")))?;
        }
        self.tx.insert(id, op);
        Ok(())
    }

    fn handle_send_completion(&mut self, user_data: u64, result: i32) {
        let Some(op) = self.tx.remove(&user_data) else {
            return;
        };
        if result < 0 {
            eprintln!(
                "dhxpro: DHCP send failed: {}",
                io::Error::from_raw_os_error(-result)
            );
        } else if result as usize != op.len() {
            eprintln!("dhxpro: short DHCP send: {} of {} bytes", result, op.len());
        }
    }

    /// Cancel and wait for every pending ring operation before returning, so
    /// the kernel cannot write into receive buffers or read send buffers after
    /// they are released. A short bounded wait prevents a wedged ring from
    /// hanging process shutdown forever.
    fn cancel_and_drain(&mut self) {
        let mut pending = Vec::with_capacity(self.tx.len() + 2);
        if self.recv_armed {
            pending.push(USER_DATA_RECV);
        }
        if self.timer_armed {
            pending.push(USER_DATA_TIMER);
        }
        pending.extend(self.tx.keys().copied());
        if pending.is_empty() {
            return;
        }

        for (index, target) in pending.iter().copied().enumerate() {
            let entry = opcode::AsyncCancel::new(target)
                .build()
                .user_data(USER_DATA_CANCEL_BASE | index as u64);
            unsafe {
                if self.ring.submission().push(&entry).is_err() {
                    break;
                }
            }
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut outstanding: Vec<u64> = pending;
        while !outstanding.is_empty() && std::time::Instant::now() < deadline {
            match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
            let mut completion = self.ring.completion();
            completion.sync();
            for cqe in &mut completion {
                let user_data = cqe.user_data();
                if let Some(position) = outstanding.iter().position(|id| *id == user_data) {
                    outstanding.swap_remove(position);
                }
                self.tx.remove(&user_data);
            }
        }

        self.tx.clear();
        self.recv_armed = false;
        self.timer_armed = false;
    }
}

impl Drop for UdpDhcpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn parse_ingress(
    msghdr: &libc::msghdr,
    data: &[u8],
    name: &libc::sockaddr_storage,
) -> Option<(Ingress, Vec<u8>)> {
    let source = sockaddr_to_socket_addr(name)?;

    let mut ifindex = 0u32;
    let mut destination = Ipv4Addr::UNSPECIFIED;
    let mut local_address = Ipv4Addr::UNSPECIFIED;
    let mut found = false;

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msghdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_PKTINFO {
                let info = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                let info = std::ptr::read_unaligned(info);
                ifindex = info.ipi_ifindex as u32;
                destination = Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr));
                local_address = Ipv4Addr::from(u32::from_be(info.ipi_spec_dst.s_addr));
                found = true;
            }
            cmsg = libc::CMSG_NXTHDR(msghdr, cmsg);
        }
    }

    if !found {
        return None;
    }
    let interface = interface_name(ifindex)?;
    Some((
        Ingress {
            ifindex,
            interface,
            destination,
            local_address,
            source,
        },
        data.to_vec(),
    ))
}

fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddrV4> {
    if storage.ss_family != libc::AF_INET as libc::sa_family_t {
        return None;
    }
    let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
    Some(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

/// Probe io_uring UDP receive/send plus `IP_PKTINFO` on the running kernel.
///
/// This is used by `smoke-test` on the target. It performs one loopback
/// exchange entirely through io_uring.
pub fn io_uring_smoke_test() -> Result<()> {
    let mut ring = IoUring::new(8)
        .map_err(|error| ring_startup_error("failed to create io_uring instance", error))?;
    probe_required_operations(&ring)?;

    let receiver = create_udp_socket(0)?;
    let sender = create_udp_socket(0)?;
    let result = (|| -> Result<()> {
        let port = socket_port(receiver).map_err(Error::Io)?;
        let payload = b"dhxpro io_uring smoke test";
        let destination = sockaddr_in(Ipv4Addr::LOCALHOST, port);

        let mut rx = ReceiveBuffers::new();
        rx.prepare();
        let recv_entry = opcode::RecvMsg::new(Fd(receiver), rx.msghdr.as_mut() as *mut _)
            .build()
            .user_data(USER_DATA_RECV);
        unsafe {
            ring.submission()
                .push(&recv_entry)
                .map_err(|error| Error::net(format!("submission queue full: {error}")))?;
        }

        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let msghdr = libc::msghdr {
            msg_name: &destination as *const _ as *mut libc::c_void,
            msg_namelen: size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let send_entry = opcode::SendMsg::new(Fd(sender), &msghdr as *const _)
            .build()
            .user_data(USER_DATA_TX_BASE);
        unsafe {
            ring.submission()
                .push(&send_entry)
                .map_err(|error| Error::net(format!("submission queue full: {error}")))?;
        }

        let mut received = 0;
        let mut sent = 0;
        while received == 0 || sent == 0 {
            ring.submit_and_wait(1)
                .map_err(|error| Error::net(format!("submit_and_wait failed: {error}")))?;
            let mut completion = ring.completion();
            completion.sync();
            for cqe in &mut completion {
                let user_data = cqe.user_data();
                let result = cqe.result();
                if result < 0 {
                    return Err(Error::net(format!(
                        "io_uring smoke operation failed: {}",
                        io::Error::from_raw_os_error(-result)
                    )));
                }
                if user_data == USER_DATA_RECV {
                    received = result as usize;
                    if received != payload.len() {
                        return Err(Error::net(format!(
                            "io_uring receive returned {received} bytes, expected {}",
                            payload.len()
                        )));
                    }
                    if &rx.data[..received] != payload {
                        return Err(Error::net("io_uring loopback payload mismatch".to_string()));
                    }
                    let mut ifindex = 0u32;
                    let mut found = false;
                    unsafe {
                        let mut cmsg = libc::CMSG_FIRSTHDR(&*rx.msghdr);
                        while !cmsg.is_null() {
                            if (*cmsg).cmsg_level == libc::IPPROTO_IP
                                && (*cmsg).cmsg_type == libc::IP_PKTINFO
                            {
                                let info = std::ptr::read_unaligned(
                                    libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo
                                );
                                ifindex = info.ipi_ifindex as u32;
                                found = true;
                            }
                            cmsg = libc::CMSG_NXTHDR(&*rx.msghdr, cmsg);
                        }
                    }
                    if !found || ifindex == 0 {
                        return Err(Error::net(
                            "io_uring RECVMSG did not deliver IP_PKTINFO metadata".to_string(),
                        ));
                    }
                } else if user_data == USER_DATA_TX_BASE {
                    sent = result as usize;
                    if sent != payload.len() {
                        return Err(Error::net(format!(
                            "io_uring send returned {sent} bytes, expected {}",
                            payload.len()
                        )));
                    }
                }
            }
        }
        Ok(())
    })();

    unsafe {
        libc::close(receiver);
        libc::close(sender);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_control_message_carries_source_and_interface() {
        let outbound = Outbound::Direct {
            destination: Ipv4Addr::BROADCAST,
            ifindex: 7,
            source: Ipv4Addr::new(192, 168, 1, 1),
            payload: vec![1, 2, 3, 4],
        };
        let op = SendOp::new(&outbound);
        assert_eq!(op.len(), 4);
        assert!(op.msghdr.msg_controllen as usize <= op.control.len() * size_of::<usize>());
        assert!(op.msghdr.msg_controllen > 0);
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&*op.msghdr);
            assert!(!cmsg.is_null());
            assert_eq!((*cmsg).cmsg_level, libc::IPPROTO_IP);
            assert_eq!((*cmsg).cmsg_type, libc::IP_PKTINFO);
            let info = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo);
            assert_eq!(info.ipi_ifindex, 7);
            assert_eq!(
                Ipv4Addr::from(u32::from_be(info.ipi_spec_dst.s_addr)),
                Ipv4Addr::new(192, 168, 1, 1)
            );
        }
    }

    #[test]
    fn relay_send_has_no_forced_source() {
        let outbound = Outbound::Relay {
            destination: Ipv4Addr::new(10, 20, 0, 1),
            payload: vec![9, 9],
        };
        let op = SendOp::new(&outbound);
        assert_eq!(op.msghdr.msg_controllen, 0);
        let addr = unsafe { &*(op.msghdr.msg_name as *const libc::sockaddr_in) };
        assert_eq!(u16::from_be(addr.sin_port), DHCP_SERVER_PORT);
    }

    #[test]
    fn socket_binds_an_unprivileged_port() {
        let socket = UdpDhcpSocket::bind(0).expect("io_uring socket bind");
        assert_ne!(socket.local_port().unwrap(), 0);
    }

    #[test]
    fn second_listener_cannot_bind_the_same_port() {
        let first = UdpDhcpSocket::bind(0).expect("io_uring socket bind");
        let port = first.local_port().unwrap();
        let error = match UdpDhcpSocket::bind(port) {
            Ok(_) => panic!("second listener bound the same port"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::Net(_)), "{error}");
    }

    #[test]
    fn receive_errors_are_classified() {
        let mut socket = UdpDhcpSocket::bind(0).expect("io_uring socket bind");
        let config = crate::config::Config::parse_str(crate::config::example_config()).unwrap();
        let mut coordinator = crate::storage::StateCoordinator::open_memory().unwrap();
        coordinator.prepare_subnets(&config, 1000).unwrap();
        let mut server =
            DhcpServer::with_store(config, coordinator, crate::storage::Clock::manual(1000))
                .unwrap();

        assert!(socket.handle_receive(-libc::EAGAIN, &mut server).is_ok());
        assert!(socket.handle_receive(-libc::ECANCELED, &mut server).is_ok());
        let error = socket
            .handle_receive(-libc::EIO, &mut server)
            .expect_err("fatal receive errors must terminate the loop");
        assert!(matches!(error, Error::Net(_)), "{error}");
    }

    #[test]
    fn shutdown_cancels_and_drains_pending_operations() {
        let mut socket = UdpDhcpSocket::bind(0).expect("io_uring socket bind");
        socket.arm_timer().expect("arm timer");
        socket.arm_receive().expect("arm receive");
        socket.ring.submit().expect("submit pending operations");
        socket.cancel_and_drain();
        assert!(!socket.recv_armed);
        assert!(!socket.timer_armed);
        assert!(socket.tx.is_empty());
    }

    #[test]
    fn io_uring_loopback_smoke_test() {
        match io_uring_smoke_test() {
            Ok(()) => {}
            Err(Error::IoUringUnavailable(message)) => {
                eprintln!("skipping io_uring smoke test: {message}");
            }
            Err(error) => panic!("io_uring smoke test failed: {error}"),
        }
    }
}
