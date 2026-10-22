//! dhxpro command line interface.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use dhxpro::admin;
use dhxpro::config::Config;
use dhxpro::error::{Error, Result};
use dhxpro::mac::MacAddr;
use dhxpro::net;
use dhxpro::preflight;
use dhxpro::server::DhcpServer;
use dhxpro::storage::{Clock, StateCoordinator, StoreOptions};

#[derive(Debug, Parser)]
#[command(
    name = "dhxpro",
    version,
    about = "Static ARM musl DHCPv4 server (io_uring + FeOxDB)"
)]
struct Cli {
    /// YAML configuration file.
    #[arg(long, global = true, default_value = "/etc/dhxpro.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse and validate the configuration, then print a summary.
    ConfigCheck,

    /// Check io_uring, storage, interfaces and state consistency.
    Preflight,

    /// Run the DHCP server in the foreground.
    Serve,

    /// Run persistent-storage and io_uring loopback smoke tests.
    SmokeTest,

    /// Inspect or administer MAC-to-IP reservations.
    Reservation {
        #[command(subcommand)]
        command: ReservationCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ReservationCommand {
    /// List every stored reservation entry.
    List,

    /// Add an enabled reservation.
    Add {
        #[arg(long)]
        mac: String,
        #[arg(long)]
        subnet: String,
        #[arg(long)]
        ip: Ipv4Addr,
        #[arg(long)]
        hostname: Option<String>,
    },

    /// Change the address of an existing reservation.
    Update {
        #[arg(long)]
        mac: String,
        #[arg(long)]
        subnet: String,
        #[arg(long)]
        ip: Ipv4Addr,
        #[arg(long, conflicts_with = "clear_hostname")]
        hostname: Option<String>,
        #[arg(long)]
        clear_hostname: bool,
    },

    /// Disable a reservation without deleting it.
    Disable {
        #[arg(long)]
        mac: String,
        #[arg(long)]
        subnet: String,
    },

    /// Re-enable a disabled reservation.
    Enable {
        #[arg(long)]
        mac: String,
        #[arg(long)]
        subnet: String,
    },

    /// Remove a reservation entry.
    Remove {
        #[arg(long)]
        mac: String,
        #[arg(long)]
        subnet: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dhxpro: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::ConfigCheck => {
            let config = Config::load(&cli.config)?;
            print_config(&config);
            println!("configuration OK");
            Ok(())
        }
        Command::Preflight => {
            let config = Config::load(&cli.config)?;
            let report = preflight::run(&config)?;
            print!("{report}");
            if report.is_healthy() {
                Ok(())
            } else {
                Err(Error::Other(format!(
                    "preflight found {} problem(s); refusing to report readiness",
                    report.problems.len()
                )))
            }
        }
        Command::Serve => serve(&cli.config),
        Command::SmokeTest => smoke_test(&cli.config),
        Command::Reservation { command } => reservation(&cli.config, command),
    }
}

fn serve(config_path: &PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;
    print_config(&config);

    // Serving without the full readiness probe would let a target with
    // incomplete io_uring or IP_PKTINFO support bind the port and then drop
    // every packet. Run the same checks as `preflight` before touching the
    // store or binding DHCP.
    let readiness = preflight::run(&config)?;
    if !readiness.is_healthy() {
        for problem in &readiness.problems {
            eprintln!("dhxpro: preflight problem: {problem}");
        }
        return Err(Error::Other(format!(
            "startup preflight found {} problem(s); refusing to serve",
            readiness.problems.len()
        )));
    }

    let store = StoreOptions::from_config(&config.storage);
    eprintln!(
        "dhxpro: opening persistent store {}",
        config.storage.path.display()
    );
    let mut server = DhcpServer::new(config, store)?;
    eprintln!("dhxpro: storage health: {:?}", server.health());
    net::install_signal_handlers()?;
    let mut socket = net::UdpDhcpSocket::bind_dhcp()?;
    socket.run(&mut server)?;
    eprintln!("dhxpro: stopped");
    Ok(())
}

fn smoke_test(config_path: &PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;
    let options = StoreOptions::from_config(&config.storage);
    println!("storage smoke test: {}", config.storage.path.display());
    preflight::storage_smoke_test(&options)
        .map_err(|error| Error::Other(format!("storage smoke test failed: {error}")))?;
    println!("storage smoke test: PASS (put/get/CAS/prefix/flush/reopen)");

    println!("io_uring smoke test: ring + UDP RECVMSG/SENDMSG + IP_PKTINFO");
    net::io_uring_smoke_test()
        .map_err(|error| Error::Other(format!("io_uring smoke test failed: {error}")))?;
    println!("io_uring smoke test: PASS");
    Ok(())
}

fn reservation(config_path: &PathBuf, command: ReservationCommand) -> Result<()> {
    let config = Config::load(config_path)?;
    let options = StoreOptions::from_config(&config.storage);
    let mut coordinator = StateCoordinator::open(&options)?;
    let now = Clock::system()?.now();

    match command {
        ReservationCommand::List => {
            let records = admin::list(&coordinator)?;
            if records.is_empty() {
                println!("no reservations");
                return Ok(());
            }
            println!(
                "{:<12}  {:<16}  {:<15}  {:<8}  {:<24}  UPDATED",
                "MAC", "SUBNET", "IP", "STATE", "HOSTNAME"
            );
            for record in records {
                for (subnet_id, entry) in record.entries_by_subnet {
                    println!(
                        "{:<12}  {:<16}  {:<15}  {:<8}  {:<24}  {}",
                        record.mac,
                        subnet_id,
                        entry.ip,
                        if entry.enabled { "enabled" } else { "disabled" },
                        entry.hostname.as_deref().unwrap_or("-"),
                        entry.updated_at
                    );
                }
            }
            Ok(())
        }
        ReservationCommand::Add {
            mac,
            subnet,
            ip,
            hostname,
        } => {
            let mac = MacAddr::parse(&mac)?;
            admin::add(
                &mut coordinator,
                &config,
                mac,
                &subnet,
                ip,
                hostname.as_deref(),
                now,
            )?;
            println!("reservation added: {mac} subnet {subnet:?} -> {ip}");
            Ok(())
        }
        ReservationCommand::Update {
            mac,
            subnet,
            ip,
            hostname,
            clear_hostname,
        } => {
            let mac = MacAddr::parse(&mac)?;
            let hostname = if clear_hostname {
                Some(None)
            } else {
                hostname.map(Some)
            };
            admin::update(&mut coordinator, &config, mac, &subnet, ip, hostname, now)?;
            println!("reservation updated: {mac} subnet {subnet:?} -> {ip}");
            Ok(())
        }
        ReservationCommand::Disable { mac, subnet } => {
            let mac = MacAddr::parse(&mac)?;
            admin::disable(&mut coordinator, mac, &subnet, now)?;
            println!("reservation disabled: {mac} subnet {subnet:?}");
            Ok(())
        }
        ReservationCommand::Enable { mac, subnet } => {
            let mac = MacAddr::parse(&mac)?;
            admin::enable(&mut coordinator, &config, mac, &subnet, now)?;
            println!("reservation enabled: {mac} subnet {subnet:?}");
            Ok(())
        }
        ReservationCommand::Remove { mac, subnet } => {
            let mac = MacAddr::parse(&mac)?;
            admin::remove(&mut coordinator, mac, &subnet, now)?;
            println!("reservation removed: {mac} subnet {subnet:?}");
            Ok(())
        }
    }
}

fn print_config(config: &Config) {
    println!("{}", config.summary());
    println!(
        "authoritative: {}; storage: {} ({} MiB file, {} MiB memory, hash bits {})",
        config.authoritative,
        config.storage.path.display(),
        config.storage.file_size_mib,
        config.storage.max_memory_mib,
        config.storage.hash_bits
    );
    for subnet in &config.subnets {
        println!(
            "subnet {:?}: {} on {}; server {}; range {}..={}; strategy {}; lease {}s; \
             offer hold {}s; decline hold {}s; exclusions {}",
            subnet.id,
            subnet.cidr,
            subnet.interface.as_deref().unwrap_or("(relay only)"),
            subnet.server_identifier,
            subnet.range_start,
            subnet.range_end,
            subnet.allocation_strategy,
            subnet.lease_seconds,
            subnet.offer_hold_seconds,
            subnet.decline_hold_seconds,
            subnet.exclusions.len()
        );
    }
    for relay in &config.relays {
        println!("relay {} -> subnet {:?}", relay.giaddr, relay.subnet_id);
    }
}
