use crate::config::Config;
use crate::qkd_manager::{PreInitQkdKeyWrapper, QkdManager};
use crate::{io_err, KmeId, DEFAULT_SHOULD_IGNORE_SYSTEM_PROXY_INTER_KME, QKD_KEY_SIZE_BYTES};
use log::error;
use notify::event::{AccessKind, AccessMode};
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::io;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Time between two checks of the size of a new key file
const KEY_FILE_SIZE_CHECK_INTERVAL: Duration = Duration::from_millis(200);
/// Maximum number of checks of the size of a new key file
const KEY_FILE_SIZE_CHECK_COUNT: u32 = 50;

pub(super) struct ConfigExtractor {}

impl ConfigExtractor {
    pub(super) async fn extract_config_to_qkd_manager(config: &Config) -> Result<Arc<QkdManager>, io::Error> {
        let qkd_manager = Arc::new(QkdManager::new(&config.this_kme_config.db_uri, config.this_kme_config.id, &config.this_kme_config.nickname).await?);
        Self::extract_all_saes(Arc::clone(&qkd_manager), config).await?;
        Self::extract_other_kmes_and_keys(Arc::clone(&qkd_manager), config).await?;
        Self::add_classical_net_routing_info_kmes(Arc::clone(&qkd_manager), config).await?;
        Ok(qkd_manager)
    }

    async fn extract_other_kmes_and_keys(qkd_manager: Arc<QkdManager>, config: &Config) -> Result<(), io::Error> {
        for other_kme_config in &config.other_kme_configs {
            let kme_id = other_kme_config.id;
            let kme_keys_dir = other_kme_config.key_directory_to_watch.as_str();
            Self::extract_and_watch_raw_keys_dir(Arc::clone(&qkd_manager), kme_id, kme_keys_dir, config.this_kme_config.delete_key_file_after_read).await?;
        }
        Self::extract_and_watch_raw_keys_dir(
            Arc::clone(&qkd_manager),
            config.this_kme_config.id,
            config.this_kme_config.key_directory_to_watch.as_str(),
            config.this_kme_config.delete_key_file_after_read).await?;
        Ok(())
    }

    async fn extract_and_watch_raw_keys_dir(qkd_manager: Arc<QkdManager>, kme_id: KmeId, kme_keys_dir: &str, delete_key_files_afterwards: bool) -> Result<(), io::Error> {
        let mut dir_watchers = qkd_manager.dir_watcher.lock().await;
        let qkd_manager = Arc::clone(&qkd_manager);

        // The files that are already in the database. The watcher must not import them again:
        // some backends report events for files that existed before the start of the watch.
        let imported_key_files = Arc::new(Mutex::new(
            Self::extract_all_keys_from_dir(Arc::clone(&qkd_manager), kme_keys_dir, kme_id, delete_key_files_afterwards).await?
        ));

        // notify-rs invokes this callback from its own thread, which is outside the Tokio
        // runtime: calling tokio::spawn there panics with "there is no reactor running"
        // and every key file dropped into the directory at runtime is silently lost.
        // Grab a runtime handle while still inside the runtime and spawn through it.
        let runtime_handle = tokio::runtime::Handle::current();

        let mut key_dir_watcher_callback = match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            let event = match res {
                Ok(event) => event,
                Err(e) => {
                    error!("Watch error: {:?}", e);
                    return;
                }
            };
            // Only the inotify backend emits Access(Close(Write)), which tells us that the
            // writer closed the file. The fsevent, kqueue, windows and poll backends emit
            // Create and Modify events instead, and kqueue and windows only give
            // ModifyKind::Any. We accept all of them, then we wait until the file is complete.
            // Each path is imported one time only, so the extra event kinds are harmless.
            if !matches!(
                event.kind,
                EventKind::Access(AccessKind::Close(AccessMode::Write))
                    | EventKind::Create(_)
                    | EventKind::Modify(_)
            ) {
                return;
            }
            for path in event.paths {
                match path.to_str() {
                    None => {
                        error!("Error converting path to string");
                        continue;
                    }
                    Some(path_as_str) => {
                        if !Self::check_file_extension_qkd_keys(path_as_str) {
                            continue;
                        }
                    }
                }
                if !Self::reserve_key_file(&imported_key_files, &path) {
                    continue;
                }
                let qkd_manager = Arc::clone(&qkd_manager);
                let imported_key_files = Arc::clone(&imported_key_files);
                runtime_handle.spawn(async move {
                    if Self::wait_for_complete_key_file(&path).await {
                        if let Some(path_as_str) = path.to_str() {
                            if Self::extract_all_keys_from_file(qkd_manager, path_as_str, kme_id, delete_key_files_afterwards).await.is_ok() {
                                return;
                            }
                            error!("Error extracting keys from file {:?}", path);
                        }
                    }
                    // The import did not occur, thus a later event can try again
                    Self::free_key_file(&imported_key_files, &path);
                });
            }
        }) {
            Ok(watcher) => watcher,
            Err(e) => {
                return Err(io_err(&format!("Error creating watcher: {:?}", e)));
            }
        };
        if key_dir_watcher_callback.watch(Path::new(kme_keys_dir), RecursiveMode::NonRecursive).is_err() {
            return Err(io_err(&format!("Error watching directory: {:?}", kme_keys_dir)));
        }
        dir_watchers.push(key_dir_watcher_callback);
        Ok(())
    }

    async fn extract_all_saes(qkd_manager: Arc<QkdManager>, config: &Config) -> Result<(), io::Error> {
        for sae_config in &config.sae_configs {
            qkd_manager.add_sae(sae_config.id, sae_config.kme_id, &sae_config.https_client_certificate_serial).await
                .map_err(|e|
                    io_err(&format!("Cannot add SAE config: {:?}", e))
                )?;
        }
        Ok(())
    }


    async fn extract_all_keys_from_file(qkd_manager: Arc<QkdManager>, file_path: &str, other_kme_id: i64, delete_file_afterwards: bool) -> Result<(), io::Error> {
        let key_file_metadata = std::fs::metadata(file_path).map_err(|e|
            io_err(&format!("Cannot read file metadata: {:?}", e))
        )?;
        if !key_file_metadata.is_file() {
            return Err(io_err("Path is not a file"));
        }
        let file = std::fs::File::open(file_path).map_err(|e|
            io_err(&format!("Cannot open file: {:?}", e))
        )?;

        let keys_count = key_file_metadata.len() / QKD_KEY_SIZE_BYTES as u64;

        let mut reader = BufReader::with_capacity(QKD_KEY_SIZE_BYTES, file);
        let mut buffer = [0; QKD_KEY_SIZE_BYTES];
        let mut qkd_keys = Vec::with_capacity(keys_count as usize);
        while let Ok(_) = reader.read_exact(&mut buffer) {
            let qkd_key = PreInitQkdKeyWrapper::new(
                other_kme_id,
                &buffer,
            ).map_err(|e|
                io_err(&format!("Cannot create QKD key: {:?}", e))
            )?;
            qkd_keys.push(qkd_key);
        }
        qkd_manager.add_multiple_pre_init_qkd_keys(qkd_keys).await.map_err(|e|
            io_err(&format!("Cannot import QKD keys from file: {:?}", e))
        )?;
        if delete_file_afterwards {
            std::fs::remove_file(file_path).map_err(|e|
                io_err(&format!("Cannot delete file after reading: {:?}", e))
            )?;
        }
        Ok(())
    }

    /// Reads every key file in a directory and returns the paths of the files that it read
    async fn extract_all_keys_from_dir(qkd_manager: Arc<QkdManager>, dir_path: &str, other_kme_id: i64, delete_key_files_afterwards: bool) -> Result<HashSet<PathBuf>, io::Error> {
        let mut imported_paths = HashSet::new();
        let paths = std::fs::read_dir(dir_path).map_err(|e|
            io_err(&format!("Cannot read directory: {:?}", e))
        )?;
        for path in paths {
            let path = match path {
                Ok(p) => p.path(),
                Err(ref e) => {
                    error!("Error reading directory entry: {:?}, {:?}", e, path);
                    continue;
                }
            };
            if path.is_file() {
                let path_as_str = path.to_str().ok_or(io_err("Error converting path to string"))?;
                if Self::check_file_extension_qkd_keys(path_as_str) {
                    Self::extract_all_keys_from_file(Arc::clone(&qkd_manager), path_as_str, other_kme_id, delete_key_files_afterwards).await?;
                    imported_paths.insert(path.clone());
                }
            }
        }
        Ok(imported_paths)
    }

    /// Reserves a path, so that two events cannot import the same file at the same time.
    /// Returns true if this call reserved the path.
    fn reserve_key_file(imported_key_files: &Mutex<HashSet<PathBuf>>, path: &Path) -> bool {
        match imported_key_files.lock() {
            Ok(mut imported_key_files) => imported_key_files.insert(path.to_path_buf()),
            Err(e) => {
                error!("Cannot lock the list of imported key files: {:?}", e);
                false
            }
        }
    }

    /// Removes a path from the reserved paths
    fn free_key_file(imported_key_files: &Mutex<HashSet<PathBuf>>, path: &Path) {
        match imported_key_files.lock() {
            Ok(mut imported_key_files) => {
                imported_key_files.remove(path);
            }
            Err(e) => error!("Cannot lock the list of imported key files: {:?}", e),
        }
    }

    /// Waits until the size of a file is the same in two consecutive checks.
    /// The fsevent, kqueue, windows and poll backends report a new file before the writer
    /// closes it. Thus the file can be incomplete when the event arrives.
    async fn wait_for_complete_key_file(path: &Path) -> bool {
        let mut previous_size: Option<u64> = None;
        for _ in 0..KEY_FILE_SIZE_CHECK_COUNT {
            let size = match std::fs::metadata(path) {
                Ok(metadata) if metadata.is_file() => metadata.len(),
                _ => return false,
            };
            if size > 0 && previous_size == Some(size) {
                return true;
            }
            previous_size = Some(size);
            tokio::time::sleep(KEY_FILE_SIZE_CHECK_INTERVAL).await;
        }
        error!("The size of the key file {:?} does not become stable, thus it is ignored", path);
        false
    }

    fn check_file_extension_qkd_keys(file_path: &str) -> bool {
        let file_ext = Path::new(file_path).extension();
        if let Some(ext) = file_ext {
            return ext == crate::QKD_KEY_FILE_EXTENSION;
        }
        false
    }

    async fn add_classical_net_routing_info_kmes(qkd_manager: Arc<QkdManager>, config: &Config) -> Result<(), io::Error> {
        for other_kme_config in &config.other_kme_configs {
            qkd_manager.add_kme_classical_net_info(other_kme_config.id,
                                                   &other_kme_config.inter_kme_bind_address,
                                                   &other_kme_config.https_client_authentication_certificate,
                                                   &other_kme_config.https_client_authentication_certificate_password,
                                                    other_kme_config.ignore_system_proxy_settings.unwrap_or(DEFAULT_SHOULD_IGNORE_SYSTEM_PROXY_INTER_KME)).await
                .map_err(|e|
                    io_err(&format!("Cannot add KME classical network info: {:?}", e))
                )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::qkd_manager::config_extractor::ConfigExtractor;
    use crate::RequestedKeyCount;
    use serial_test::serial;
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::Arc;

    #[tokio::test]
    #[serial]
    async fn test_extract_config_to_qkd_manager() {
        #[cfg(not(target_os = "macos"))]
        const CONFIG_PATH: &'static str = "tests/data/test_kme_config.json5";
        #[cfg(target_os = "macos")]
        const CONFIG_PATH: &'static str = "tests/data/test_kme_config_macos.json5";

        let config = Config::from_json_path(CONFIG_PATH).unwrap();
        let qkd_manager = ConfigExtractor::extract_config_to_qkd_manager(&config).await.unwrap();
        assert_eq!(qkd_manager.kme_id, 1);
        assert!(qkd_manager.get_qkd_keys(2, &vec![0x70, 0xF4, 0x4F, 0x56, 0x0C, 0x3F, 0x27, 0xD4, 0xB2, 0x11, 0xA4, 0x78, 0x13, 0xAF, 0xD0, 0x3C, 0x03, 0x81, 0x3B, 0x8E], RequestedKeyCount::new(1).unwrap()).await.is_ok());
    }

    #[test]
    fn test_file_extension_check() {
        assert!(ConfigExtractor::check_file_extension_qkd_keys("path/to/test_file.cor"));
        assert!(!ConfigExtractor::check_file_extension_qkd_keys("test_file.bad_ext"));
        assert!(!ConfigExtractor::check_file_extension_qkd_keys("path/to/test_file.bad_ext"));
        assert!(!ConfigExtractor::check_file_extension_qkd_keys("test_file"));
        assert!(!ConfigExtractor::check_file_extension_qkd_keys("path/to/test_file"));
    }

    #[tokio::test]
    async fn test_extract_all_keys_from_dir() {
        let qkd_manager = Arc::new(crate::qkd_manager::QkdManager::new(":memory:", 1, &None).await.unwrap());
        assert!(ConfigExtractor::extract_all_keys_from_dir(Arc::clone(&qkd_manager), "raw_keys/kme-1-1", 1, false).await.is_ok());
        assert!(ConfigExtractor::extract_all_keys_from_dir(qkd_manager, "unexisting/directory", 1, false).await.is_err());
    }

    #[tokio::test]
    async fn test_extract_all_keys_from_file() {
        let qkd_manager = Arc::new(crate::qkd_manager::QkdManager::new(":memory:", 1, &None).await.unwrap());
        assert!(ConfigExtractor::extract_all_keys_from_file(Arc::clone(&qkd_manager), "raw_keys/", 1, false).await.is_err());
        assert!(ConfigExtractor::extract_all_keys_from_file(Arc::clone(&qkd_manager), "path/to/unexisting/file", 1, false).await.is_err());
        assert!(ConfigExtractor::extract_all_keys_from_file(Arc::clone(&qkd_manager), "raw_keys/kme-1-1/211202_1159_CD6ADBF2.cor", 1, false).await.is_ok());
    }

    #[tokio::test]
    async fn test_extract_and_watch_raw_keys_dir() {
        let qkd_manager = Arc::new(crate::qkd_manager::QkdManager::new(":memory:", 1, &None).await.unwrap());
        assert!(ConfigExtractor::extract_and_watch_raw_keys_dir(Arc::clone(&qkd_manager), 1, "raw_keys/kme-1-1", false).await.is_ok());
        assert!(ConfigExtractor::extract_and_watch_raw_keys_dir(Arc::clone(&qkd_manager), 1, "unexisting/directory", false).await.is_err());
    }

    #[tokio::test]
    async fn test_watched_dir_imports_key_file_written_at_runtime() {
        // Regression test: the notify callback used to call `tokio::spawn` from notify-rs'
        // own thread, panicking with "there is no reactor running". The watcher thread died
        // and every key file dropped into the directory while running was silently lost.
        const SAE1_CERT_SERIAL: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        const SAE2_CERT_SERIAL: [u8; 4] = [0x05, 0x06, 0x07, 0x08];
        const TMP_DIR: &'static str = "tests/tmp/watch_runtime_key_file";

        let _ = std::fs::remove_dir_all(TMP_DIR);
        std::fs::create_dir_all(TMP_DIR).unwrap();

        let qkd_manager = Arc::new(crate::qkd_manager::QkdManager::new(":memory:", 1, &None).await.unwrap());
        qkd_manager.add_sae(1, 1, &Some(Vec::from(SAE1_CERT_SERIAL))).await.unwrap();
        qkd_manager.add_sae(2, 1, &Some(Vec::from(SAE2_CERT_SERIAL))).await.unwrap();
        ConfigExtractor::extract_and_watch_raw_keys_dir(Arc::clone(&qkd_manager), 1, TMP_DIR, false).await.unwrap();

        // Nothing in the directory yet, so no key can be delivered
        assert!(qkd_manager.get_qkd_keys(2, &Vec::from(SAE1_CERT_SERIAL), RequestedKeyCount::new(1).unwrap()).await.is_err());

        std::fs::write(format!("{}/runtime_key.cor", TMP_DIR), [0x42u8; crate::QKD_KEY_SIZE_BYTES]).unwrap();

        // Import is triggered by the file-close event and completes asynchronously
        let mut imported = false;
        // The watcher waits for the size of the file to become stable, and the fsevent and
        // windows backends can report the file some time after the write
        for _ in 0..150 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if qkd_manager.get_qkd_keys(2, &Vec::from(SAE1_CERT_SERIAL), RequestedKeyCount::new(1).unwrap()).await.is_ok() {
                imported = true;
                break;
            }
        }
        let _ = std::fs::remove_dir_all(TMP_DIR);
        assert!(imported, "key file written into the watched directory was never imported");
    }


    #[test]
    fn test_reserve_and_free_key_file() {
        let imported_key_files = Mutex::new(HashSet::new());
        let path = PathBuf::from("tests/tmp/a_key_file.cor");

        // The first call reserves the path, the second call must not
        assert!(ConfigExtractor::reserve_key_file(&imported_key_files, &path));
        assert!(!ConfigExtractor::reserve_key_file(&imported_key_files, &path));

        // After a free, a new reservation is possible again
        ConfigExtractor::free_key_file(&imported_key_files, &path);
        assert!(ConfigExtractor::reserve_key_file(&imported_key_files, &path));

        // A different path is independent
        let other_path = PathBuf::from("tests/tmp/an_other_key_file.cor");
        assert!(ConfigExtractor::reserve_key_file(&imported_key_files, &other_path));
    }

    #[tokio::test]
    async fn test_wait_for_complete_key_file() {
        const TMP_DIR: &'static str = "tests/tmp/complete_key_file";
        let _ = std::fs::remove_dir_all(TMP_DIR);
        std::fs::create_dir_all(TMP_DIR).unwrap();

        // A file that does not change is complete
        let complete_file = format!("{}/complete.cor", TMP_DIR);
        std::fs::write(&complete_file, [0x42u8; crate::QKD_KEY_SIZE_BYTES]).unwrap();
        assert!(ConfigExtractor::wait_for_complete_key_file(Path::new(&complete_file)).await);

        // A file that does not exist is not complete
        let absent_file = format!("{}/absent.cor", TMP_DIR);
        assert!(!ConfigExtractor::wait_for_complete_key_file(Path::new(&absent_file)).await);

        // A directory is not a key file
        assert!(!ConfigExtractor::wait_for_complete_key_file(Path::new(TMP_DIR)).await);

        let _ = std::fs::remove_dir_all(TMP_DIR);
    }
}
