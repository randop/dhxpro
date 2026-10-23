//! Typed FeOxDB access.
//!
//! FeOxDB provides atomic single-key operations but no multi-key transaction.
//! The coordinator in [`super::coordinator`] layers an idempotent redo journal
//! on top of the raw repository so that lease, IP-owner and cursor updates
//! recover as one logical mutation.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use feoxdb::FeoxStore;

use crate::config::StorageConfig;
use crate::error::{Error, Result};
use crate::keys;
use crate::mac::MacAddr;
use crate::model::{
    decode_record, encode_record, IpOwner, JournalIntent, LeaseRecord, ReservationRecord,
    SubnetMeta,
};

/// Page size used for prefix scans. `range_query` requires a finite limit, so
/// scans are paginated to avoid silently truncating large collections.
const SCAN_PAGE: usize = 4096;
/// Hard cap protecting the embedded target from unbounded memory growth if the
/// store is unexpectedly large.
const SCAN_MAX_RECORDS: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct StoreOptions {
    /// `None` selects an in-memory store (tests and read-only tooling only).
    pub path: Option<PathBuf>,
    pub file_size_bytes: u64,
    pub max_memory_bytes: usize,
    pub hash_bits: u32,
}

impl StoreOptions {
    pub fn from_config(storage: &StorageConfig) -> Self {
        Self {
            path: Some(storage.path.clone()),
            file_size_bytes: storage.file_size_bytes(),
            max_memory_bytes: storage.max_memory_bytes(),
            hash_bits: storage.hash_bits,
        }
    }

    pub fn memory() -> Self {
        Self {
            path: None,
            file_size_bytes: 0,
            max_memory_bytes: 0,
            hash_bits: 0,
        }
    }
}

/// Exclusive advisory lock guarding the single-writer invariant.
///
/// FeOxDB itself does not lock the device file, so dhxpro creates a sibling
/// `.lock` file and takes a non-blocking `flock`. The lock is released when
/// the process exits, even after a crash.
pub struct StoreLock {
    file: File,
    path: PathBuf,
}

impl StoreLock {
    pub fn acquire(store_path: &Path) -> Result<Self> {
        let mut lock_name = store_path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let path = PathBuf::from(lock_name);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK)
                || error.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(Error::StoreLocked(path));
            }
            return Err(Error::Io(error));
        }

        // Best-effort PID record for operators. The lock itself is what
        // enforces exclusivity.
        let _ = file.set_len(0);
        let _ = writeln!(file, "{}", std::process::id());

        Ok(Self { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Thin, typed wrapper over a FeOxStore.
pub struct Repo {
    store: FeoxStore,
    lock: Option<StoreLock>,
    path: Option<PathBuf>,
}

impl Repo {
    pub fn open(options: &StoreOptions) -> Result<Self> {
        let lock = match &options.path {
            Some(path) => Some(StoreLock::acquire(path)?),
            None => None,
        };

        let store = match &options.path {
            Some(path) => {
                let path = path.to_str().ok_or_else(|| {
                    Error::State(format!("storage path {:?} is not valid UTF-8", path))
                })?;
                let file_size = if options.file_size_bytes == 0 {
                    64 * 1024 * 1024
                } else {
                    options.file_size_bytes
                };
                let max_memory = if options.max_memory_bytes == 0 {
                    64 * 1024 * 1024
                } else {
                    options.max_memory_bytes
                };
                let hash_bits = if options.hash_bits == 0 {
                    16
                } else {
                    options.hash_bits
                };
                FeoxStore::builder()
                    .device_path(path)
                    .file_size(file_size)
                    .max_memory(max_memory)
                    .hash_bits(hash_bits)
                    .enable_ttl(false)
                    .build()?
            }
            None => FeoxStore::new(None)?,
        };

        Ok(Self {
            store,
            lock,
            path: options.path.clone(),
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn lock_path(&self) -> Option<&Path> {
        self.lock.as_ref().map(StoreLock::path)
    }

    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    pub fn flush(&self) -> Result<()> {
        self.store.flush()?;
        Ok(())
    }

    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.store.get(key) {
            Ok(value) => Ok(Some(value)),
            Err(feoxdb::FeoxError::KeyNotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn put_raw(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.store.insert(key, value)?;
        Ok(())
    }

    /// Idempotent delete: a missing key is treated as already deleted.
    pub fn delete_raw(&self, key: &[u8]) -> Result<()> {
        match self.store.delete(key) {
            Ok(()) => Ok(()),
            Err(feoxdb::FeoxError::KeyNotFound) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Scan every key sharing `prefix`, paginating through `range_query`.
    pub fn scan_prefix(&self, prefix: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let (mut start, end) = keys::prefix_bounds(prefix);
        let mut out = Vec::new();
        loop {
            let page = self.store.range_query(&start, &end, SCAN_PAGE)?;
            let page_len = page.len();
            if let Some((last_key, _)) = page.last() {
                start = last_key.clone();
                start.push(0);
            }
            out.extend(page);
            if out.len() > SCAN_MAX_RECORDS {
                return Err(Error::State(format!(
                    "prefix scan for {prefix:?} exceeded {SCAN_MAX_RECORDS} records"
                )));
            }
            if page_len < SCAN_PAGE {
                break;
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Reservations
    // ------------------------------------------------------------------

    pub fn reservation(&self, mac: MacAddr) -> Result<Option<ReservationRecord>> {
        let key = keys::reservation_key(mac);
        let Some(raw) = self.get_raw(key.as_bytes())? else {
            return Ok(None);
        };
        let record: ReservationRecord = decode_record(&raw)?;
        validate_reservation(&record, mac, &key)?;
        Ok(Some(record))
    }

    pub fn put_reservation(&self, record: &ReservationRecord) -> Result<()> {
        let key = keys::reservation_key(record.mac);
        validate_reservation(record, record.mac, &key)?;
        self.put_raw(key.as_bytes(), &encode_record(record)?)
    }

    pub fn delete_reservation(&self, mac: MacAddr) -> Result<()> {
        let key = keys::reservation_key(mac);
        self.delete_raw(key.as_bytes())
    }

    pub fn reservations(&self) -> Result<Vec<ReservationRecord>> {
        self.scan_prefix(keys::RESERVATION_PREFIX)?
            .into_iter()
            .map(|(key, raw)| {
                let record: ReservationRecord = decode_record(&raw)?;
                let mac = mac_from_key(&key, keys::RESERVATION_PREFIX)?;
                validate_reservation(&record, mac, &String::from_utf8_lossy(&key))?;
                Ok(record)
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Leases
    // ------------------------------------------------------------------

    pub fn lease(&self, mac: MacAddr) -> Result<Option<LeaseRecord>> {
        let key = keys::lease_key(mac);
        let Some(raw) = self.get_raw(key.as_bytes())? else {
            return Ok(None);
        };
        let record: LeaseRecord = decode_record(&raw)?;
        validate_lease(&record, mac, &key)?;
        Ok(Some(record))
    }

    pub fn put_lease(&self, record: &LeaseRecord) -> Result<()> {
        let key = keys::lease_key(record.mac);
        validate_lease(record, record.mac, &key)?;
        self.put_raw(key.as_bytes(), &encode_record(record)?)
    }

    pub fn delete_lease(&self, mac: MacAddr) -> Result<()> {
        let key = keys::lease_key(mac);
        self.delete_raw(key.as_bytes())
    }

    pub fn leases(&self) -> Result<Vec<LeaseRecord>> {
        self.scan_prefix(keys::LEASE_PREFIX)?
            .into_iter()
            .map(|(key, raw)| {
                let record: LeaseRecord = decode_record(&raw)?;
                let mac = mac_from_key(&key, keys::LEASE_PREFIX)?;
                validate_lease(&record, mac, &String::from_utf8_lossy(&key))?;
                Ok(record)
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // IP owner index
    // ------------------------------------------------------------------

    pub fn owner(&self, ip: Ipv4Addr) -> Result<Option<IpOwner>> {
        let key = keys::ip_owner_key(ip);
        let Some(raw) = self.get_raw(key.as_bytes())? else {
            return Ok(None);
        };
        let owner: IpOwner = decode_record(&raw)?;
        if owner.ip != ip {
            return Err(Error::State(format!(
                "IP owner record at {key} claims address {}",
                owner.ip
            )));
        }
        Ok(Some(owner))
    }

    pub fn put_owner(&self, owner: &IpOwner) -> Result<()> {
        if owner.subnet_id.is_empty() || owner.subnet_id.len() > 64 {
            return Err(Error::State(
                "IP owner has an invalid subnet id".to_string(),
            ));
        }
        let key = keys::ip_owner_key(owner.ip);
        self.put_raw(key.as_bytes(), &encode_record(owner)?)
    }

    pub fn delete_owner(&self, ip: Ipv4Addr) -> Result<()> {
        let key = keys::ip_owner_key(ip);
        self.delete_raw(key.as_bytes())
    }

    pub fn owners(&self) -> Result<Vec<IpOwner>> {
        self.scan_prefix(keys::IP_OWNER_PREFIX)?
            .into_iter()
            .map(|(key, raw)| {
                let owner: IpOwner = decode_record(&raw)?;
                let ip = ip_from_key(&key, keys::IP_OWNER_PREFIX)?;
                if owner.ip != ip {
                    return Err(Error::State(format!(
                        "IP owner record for {ip} claims address {}",
                        owner.ip
                    )));
                }
                Ok(owner)
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Subnet metadata
    // ------------------------------------------------------------------

    pub fn subnet_meta(&self, subnet_id: &str) -> Result<Option<SubnetMeta>> {
        let key = keys::subnet_key(subnet_id);
        let Some(raw) = self.get_raw(key.as_bytes())? else {
            return Ok(None);
        };
        let meta: SubnetMeta = decode_record(&raw)?;
        if meta.subnet_id != subnet_id {
            return Err(Error::State(format!(
                "subnet metadata at {key} claims subnet {:?}",
                meta.subnet_id
            )));
        }
        Ok(Some(meta))
    }

    pub fn put_subnet_meta(&self, meta: &SubnetMeta) -> Result<()> {
        if meta.subnet_id.is_empty() || meta.subnet_id.len() > 64 {
            return Err(Error::State(
                "subnet metadata has an invalid subnet id".to_string(),
            ));
        }
        let key = keys::subnet_key(&meta.subnet_id);
        self.put_raw(key.as_bytes(), &encode_record(meta)?)
    }

    // ------------------------------------------------------------------
    // Journal intents
    // ------------------------------------------------------------------

    pub fn intents(&self) -> Result<Vec<JournalIntent>> {
        let mut intents: Vec<JournalIntent> = self
            .scan_prefix(keys::TXN_PREFIX)?
            .into_iter()
            .map(|(key, raw)| {
                let intent: JournalIntent = decode_record(&raw)?;
                let sequence = keys::txn_sequence(&key).ok_or_else(|| {
                    Error::State(format!(
                        "journal key {:?} has no valid sequence",
                        String::from_utf8_lossy(&key)
                    ))
                })?;
                if intent.sequence != sequence {
                    return Err(Error::State(format!(
                        "journal record sequence {} does not match key {}",
                        intent.sequence, sequence
                    )));
                }
                intent.validate()?;
                Ok(intent)
            })
            .collect::<Result<Vec<_>>>()?;
        intents.sort_by_key(|intent| intent.sequence);
        Ok(intents)
    }

    pub fn put_intent(&self, intent: &JournalIntent) -> Result<()> {
        intent.validate()?;
        let key = keys::txn_key(intent.sequence);
        self.put_raw(key.as_bytes(), &encode_record(intent)?)
    }

    pub fn delete_intent(&self, sequence: u64) -> Result<()> {
        let key = keys::txn_key(sequence);
        self.delete_raw(key.as_bytes())
    }

    /// Verify the FeOxDB capabilities dhxpro relies on: exact-key put/get,
    /// prefix iteration, CAS, delete and durable flush. The probe key is
    /// removed before returning; a failure leaves a clear diagnostic.
    pub fn verify_capabilities(&self) -> Result<()> {
        let probe_key = "dhxpro:probe:v1:storage-check";
        let key = probe_key.as_bytes();
        self.delete_raw(key)?;
        self.put_raw(key, b"dhxpro-probe-value-v1")?;
        let value = self
            .get_raw(key)?
            .ok_or_else(|| Error::State("FeOxDB probe put/get failed".to_string()))?;
        if value != b"dhxpro-probe-value-v1" {
            return Err(Error::State(
                "FeOxDB probe returned a wrong value".to_string(),
            ));
        }
        let swapped =
            self.store
                .compare_and_swap(key, b"dhxpro-probe-value-v1", b"dhxpro-probe-value-v2")?;
        if !swapped {
            return Err(Error::State(
                "FeOxDB compare_and_swap did not apply the expected update".to_string(),
            ));
        }
        let found = self.scan_prefix("dhxpro:probe:v1:")?;
        if !found.iter().any(|(found_key, _)| found_key == key) {
            return Err(Error::State(
                "FeOxDB prefix iteration did not return the probe key".to_string(),
            ));
        }
        self.delete_raw(key)?;
        self.flush()?;
        Ok(())
    }
}

fn mac_from_key(key: &[u8], prefix: &str) -> Result<MacAddr> {
    let suffix = key
        .strip_prefix(prefix.as_bytes())
        .ok_or_else(|| Error::State(format!("key {key:?} does not start with {prefix:?}")))?;
    let text = std::str::from_utf8(suffix)
        .map_err(|_| Error::State(format!("MAC key suffix for {prefix:?} is not UTF-8")))?;
    MacAddr::parse(text)
}

fn ip_from_key(key: &[u8], prefix: &str) -> Result<Ipv4Addr> {
    let suffix = key
        .strip_prefix(prefix.as_bytes())
        .ok_or_else(|| Error::State(format!("key {key:?} does not start with {prefix:?}")))?;
    let text = std::str::from_utf8(suffix)
        .map_err(|_| Error::State(format!("IP key suffix for {prefix:?} is not UTF-8")))?;
    text.parse()
        .map_err(|_| Error::State(format!("invalid IPv4 address {text:?} in key")))
}

fn validate_reservation(
    record: &ReservationRecord,
    expected_mac: MacAddr,
    key: &str,
) -> Result<()> {
    if record.mac != expected_mac {
        return Err(Error::State(format!(
            "reservation record at {key} belongs to {} but the key names {}",
            record.mac, expected_mac
        )));
    }
    for (subnet_id, entry) in &record.entries_by_subnet {
        if entry.subnet_id != *subnet_id {
            return Err(Error::State(format!(
                "reservation entry for subnet {subnet_id:?} claims subnet {:?}",
                entry.subnet_id
            )));
        }
        if entry.subnet_id.is_empty() || entry.subnet_id.len() > 64 {
            return Err(Error::State(format!(
                "reservation record at {key} has an invalid subnet id"
            )));
        }
    }
    Ok(())
}

fn validate_lease(record: &LeaseRecord, expected_mac: MacAddr, key: &str) -> Result<()> {
    if record.mac != expected_mac {
        return Err(Error::State(format!(
            "lease record at {key} belongs to {} but the key names {}",
            record.mac, expected_mac
        )));
    }
    for (subnet_id, entry) in &record.entries_by_subnet {
        if entry.subnet_id != *subnet_id {
            return Err(Error::State(format!(
                "lease entry for subnet {subnet_id:?} claims subnet {:?}",
                entry.subnet_id
            )));
        }
        if entry.subnet_id.is_empty() || entry.subnet_id.len() > 64 {
            return Err(Error::State(format!(
                "lease record at {key} has an invalid subnet id"
            )));
        }
    }
    Ok(())
}
