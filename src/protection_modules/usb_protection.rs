// // protection_modules/usb_protection.rs
// // USB device and file protection implementation

// use crate::policy_engine::PolicyEngine;
// use crate::communication::ServerCommunicator;
// use crate::protection_modules::ProtectionModule;
// use crate::policy_constants::*;
// use serde::{Deserialize, Serialize};
// use std::collections::{HashMap, HashSet};
// use std::time::{SystemTime, UNIX_EPOCH};
// use std::path::Path;
// use log;
// use tokio::time;

// // ===== DATA STRUCTURES =====

// /// Information about a USB device
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct USBDeviceInfo {
//     pub drive_letter: String,
//     pub volume_name: String,
//     pub total_size: u64,
//     pub free_space: u64,
//     pub file_system: String,
//     pub serial_number: String,
//     pub insertion_time: u64,
// }

// /// Analysis results of files on a USB device
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct USBFileAnalysis {
//     pub total_files: usize,
//     pub total_folders: usize,
//     pub total_size: u64,
//     pub file_types: HashMap<String, usize>,
//     pub file_list: Vec<String>,
//     pub suspicious_files: Vec<String>,
// }

// // ===== USB PROTECTION MODULE =====

// /// USB protection module that monitors and controls USB devices
// pub struct USBProtection {
//     known_devices: HashSet<String>, // Track known USB devices  
//     known_files: HashSet<String>, // Track files we've already seen
//     last_scan_time: u64,             // Last scan time for rate limiting
// }

// impl USBProtection {
//     /// Create a new USB protection module
//     pub fn new() -> Self {
//         Self {
//             known_devices: HashSet::new(),
//             known_files: HashSet::new(),
//             last_scan_time: 0,
//         }
//     }
//     fn get_communicator_for_alert(&self) -> ServerCommunicator {
//         // In a real implementation, you'd return a clone of the communicator
//         // For now, we'll create a new one (this might not work for actual alerts)
//         ServerCommunicator::new()
//     }
//     /// Main monitoring logic for USB devices
//     // async fn execute_monitoring(
//     //     &mut self,
//     //     policy_engine: &PolicyEngine,
//     //     communicator: &ServerCommunicator,
//     //     agent_id: u64,
//     //     token: &str
//     // ) -> Result<(), Box<dyn std::error::Error>> {
//     //     let current_devices = self.scan_usb_devices();
        
//     //     // Detect new USB devices
//     //     for device in &current_devices {
//     //         if !self.known_devices.contains(&device.drive_letter) {
//     //             log::info!("🎯 New USB device detected: {}", device.drive_letter);
                
//     //             // Check specific policies for this device
//     //             if policy_engine.should_block_usb_devices() {
//     //                 log::warn!("🚫 USB BLOCKED by {} policy: {}", POLICY_USB_DEVICE_BLOCK, device.drive_letter);
//     //                 self.handle_blocked_usb(device, communicator, agent_id, token).await?;
//     //             } else if policy_engine.should_monitor_usb_devices() {
//     //                 log::info!("👀 USB MONITORING by {} policy: {}", POLICY_USB_DEVICE_MONITOR, device.drive_letter);
                    
//     //                 // Monitor USB and analyze files
//     //                 let file_analysis = self.analyze_usb_files(&device.drive_letter);
//     //                 self.send_usb_alert(device, &file_analysis, "MONITORED", communicator, agent_id, token).await?;
                    
//     //                 // Start file monitoring if needed
//     //                 if policy_engine.should_block_executable_files() || policy_engine.should_detect_suspicious_files() {
//     //                     self.monitor_file_operations(&device.drive_letter, policy_engine, communicator, agent_id, token).await?;
//     //                 }
//     //             }
                
//     //             self.known_devices.insert(device.drive_letter.clone());
//     //         }
//     //     }

//         // Detect removed USB devices
//     //     let current_drives: HashSet<String> = current_devices.iter()
//     //         .map(|d| d.drive_letter.clone())
//     //         .collect();
        
//     //     for known_device in &self.known_devices {
//     //         if !current_drives.contains(known_device) {
//     //             log::info!("📤 USB device removed: {}", known_device);
//     //         }
//     //     }

//     //     // Update known devices and scan time
//     //     self.known_devices = current_drives;
//     //     self.last_scan_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
//     //     Ok(())
//     // }


//     async fn execute_monitoring(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str
//     ) -> Result<(), Box<dyn std::error::Error>> {


//         let current_devices = self.scan_usb_devices();
        
//         for device in &current_devices {
//             if !self.known_devices.contains(&device.drive_letter) {
//                 log::info!("🎯 New USB device detected: {}", device.drive_letter);

//                 // --- NEW GRANULAR LOGIC ---

//                 // Policy 1: Block the entire device? This is the highest priority.
//                 if policy_engine.is_policy_active(POLICY_USB_DEVICE_BLOCK) {
//                     log::warn!("🚫 USB BLOCKED by policy: {}", device.drive_letter);
//                     self.handle_blocked_usb(device, communicator, agent_id, token).await?;
//                     // self.known_devices.insert(device.drive_letter.clone());
//                     continue; // Stop processing other policies for this device
//                 }
                
//                 // Policy 2: Just monitor the connection?
//                 if policy_engine.is_policy_active(POLICY_USB_DEVICE_MONITOR) {
//                     log::info!("👀 USB CONNECTION MONITORED: {}", device.drive_letter);
//                     let minimal_analysis = USBFileAnalysis::empty();
//                     self.send_usb_alert(device, &minimal_analysis, "MONITORED", communicator, agent_id, token).await?;
//                 }

//                 // Policy 3: Scan all files?
//                 if policy_engine.is_policy_active(POLICY_USB_SCAN_FILES) {
//                     log::info!(" SCANNING FILES on USB by policy: {}", device.drive_letter);
//                     let file_analysis = self.analyze_usb_files(&device.drive_letter);
//                     self.send_usb_alert(device, &file_analysis, "SCANNED", communicator, agent_id, token).await?;
//                 }

//                 // Policy 4 & 5: Block executables or detect suspicious files?
//                 if policy_engine.is_policy_active(POLICY_USB_BLOCK_EXECUTABLES) || policy_engine.is_policy_active(POLICY_USB_DETECT_SUSPICIOUS) {
//                     self.monitor_file_operations(&device.drive_letter, policy_engine, communicator, agent_id, token).await?;
//                 }
                
//                 self.known_devices.insert(device.drive_letter.clone());
//             }
//         }
//         let current_drives: HashSet<String> = current_devices.iter()
//         .map(|d| d.drive_letter.clone())
//         .collect();
//     let current_drives: HashSet<String> = current_devices.iter().map(|d| d.drive_letter.clone()).collect();
//     self.known_devices.retain(|known_drive| {
//         if !current_drives.contains(known_drive) {
//             log::info!("📤 USB device removed: {}", known_drive);
//             false // Remove from known_devices
//         } else {
//             true // Keep in known_devices
//         }
//     });
    
//     Ok(())
// }
//     // for known_device in &self.known_devices {
//     //     if !current_drives.contains(known_device) {
//     //         log::info!("📤 USB device removed: {}", known_device);
//     //     }
//     // }

//     // // Update known devices and scan time
//     // self.known_devices = current_drives;
//     // self.last_scan_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
//     // Ok(())
//     //     // ... (rest of the function for device removal)
//     // }


//     /// Handle a USB device that should be blocked
//     async fn handle_blocked_usb(
//         &self,
//         device: &USBDeviceInfo,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         // Create empty file analysis for blocked device
//         let file_analysis = USBFileAnalysis {
//             total_files: 0,
//             total_folders: 0,
//             total_size: 0,
//             file_types: HashMap::new(),
//             file_list: Vec::new(),
//             suspicious_files: Vec::new(),
//         };

//         // Send block alert to backend
//         self.send_usb_alert(device, &file_analysis, "BLOCKED", communicator, agent_id, token).await?;

//         // In a real implementation, you would:
//         // 1. Eject the USB device programmatically
//         // 2. Prevent any file access to the USB
//         // 3. Show user notification about blocked device
        
//         log::warn!("🛑 USB device {} has been blocked by DLP policy", device.drive_letter);
        
//         Ok(())
//     }

//     /// Monitor file operations on a USB drive
//    // usb_protection.rs - Update the monitor_file_operations method

//    // usb_protection.rs - Simplified approach without async task
// async fn monitor_file_operations(
//     &mut self,
//     drive_letter: &str,
//     policy_engine: &PolicyEngine,
//     communicator: &ServerCommunicator,
//     agent_id: u64,
//     token: &str
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let drive_path = format!("{}\\", drive_letter);
    
//     // Do a single scan instead of continuous monitoring
//     let current_files = match Self::scan_files(&drive_path) {
//         Ok(files) => files,
//         Err(_) => {
//             log::warn!("⚠️ Cannot scan files on drive {} - may be disconnected", drive_letter);
//             return Ok(());
//         }
//     };

//     // Check for new files since last scan
//     let new_files: Vec<String> = current_files.iter()
//         .filter(|file_path| !self.known_files.contains(*file_path))
//         .cloned()
//         .collect();

//     if !new_files.is_empty() {
//         log::info!("📄 Found {} new files on USB drive {}", new_files.len(), drive_letter);
        
//         for file_path in &new_files {
//             // Check for executable blocking
//             if policy_engine.should_block_executable_files() {
//                 if let Some(extension) = Path::new(file_path).extension() {
//                     let ext = extension.to_string_lossy().to_lowercase();
                    
//                     let executable_extensions = ["exe", "bat", "msi", "ps1", "cmd", "com"];
//                     if executable_extensions.contains(&ext.as_str()) {
//                         log::warn!("🚫 Executable file BLOCKED by {} policy: {} (extension: {})", 
//                                   POLICY_USB_BLOCK_EXECUTABLES, file_path, ext);
                        
//                         if let Err(e) = std::fs::remove_file(file_path) {
//                             log::error!("❌ Failed to block file {}: {}", file_path, e);
//                         } else {
//                             log::info!("✅ Blocked executable file removed: {}", file_path);
                            
//                             // Send file block alert
//                             Self::send_file_block_alert(
//                                 communicator,
//                                 agent_id,
//                                 token,
//                                 file_path,
//                                 &ext,
//                                 POLICY_USB_BLOCK_EXECUTABLES
//                             ).await?;
//                         }
//                         continue; // Skip suspicious file check
//                     }
//                 }
//             }
            
//             // Check for suspicious files
//             if policy_engine.should_detect_suspicious_files() {
//                 if let Some(extension) = Path::new(file_path).extension() {
//                     let ext = extension.to_string_lossy().to_lowercase();
//                     if self.is_suspicious_file(&ext, Path::new(file_path)) {
//                         log::warn!("⚠️ Suspicious file detected by {} policy: {}", 
//                                   POLICY_USB_DETECT_SUSPICIOUS, file_path);
                        
//                         // Send suspicious file alert
//                         Self::send_suspicious_file_alert(
//                             communicator,
//                             agent_id,
//                             token,
//                             file_path
//                         ).await?;
//                     }
//                 }
//             }
//         }
        
//         // Update known files
//         self.known_files.extend(new_files);
//     }

//     Ok(())
// }
//     // ===== UTILITY METHODS =====

//     /// Scan files in a directory
//     fn scan_files(drive_path: &str) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
//         let mut files = HashSet::new();
        
//         if let Ok(entries) = std::fs::read_dir(drive_path) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
//                 if path.is_file() {
//                     if let Some(path_str) = path.to_str() {
//                         files.insert(path_str.to_string());
//                     }
//                 }
//             }
//         }
        
//         Ok(files)
//     }

//     /// Send file block alert to backend
//     async fn send_file_block_alert(
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//         file_path: &str,
//         file_extension: &str,
//         policy_code: &str
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         let alert_data = serde_json::json!({
//             "agentId": agent_id,
//             "alertType": "FILE_BLOCKED",
//             "description": format!("File blocked by {} policy: {} (Extension: {})", policy_code, file_path, file_extension),
//             "deviceInfo": "USB Device",
//             "fileDetails": format!("Blocked file: {}, Extension: {}, Policy: {}", file_path, file_extension, policy_code),
//             "severity": "HIGH",
//             "actionTaken": "BLOCKED",
//             "policyCode": policy_code
//         });

//         communicator.send_alert(&alert_data, token).await?;
//         log::info!("📤 Sent file block alert for: {} (Policy: {})", file_path, policy_code);
//         Ok(())
//     }

//     /// Send suspicious file alert to backend
//     async fn send_suspicious_file_alert(
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//         file_path: &str
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         let alert_data = serde_json::json!({
//             "agentId": agent_id,
//             "alertType": "SUSPICIOUS_FILE_DETECTED",
//             "description": format!("Suspicious file detected on USB: {}", file_path),
//             "deviceInfo": "USB Device", 
//             "fileDetails": format!("Suspicious file: {}", file_path),
//             "severity": "MEDIUM",
//             "actionTaken": "DETECTED",
//             "policyCode": POLICY_USB_DETECT_SUSPICIOUS
//         });

//         communicator.send_alert(&alert_data, token).await?;
//         log::info!("📤 Sent suspicious file alert for: {}", file_path);
//         Ok(())
//     }

// //     /// Scan for USB devices on the system
// //     pub fn scan_usb_devices(&self) -> Vec<USBDeviceInfo> {
// //         let mut devices = Vec::new();
        
// //         log::info!("🔍 Scanning for USB devices on all drives...");
        
// //         // Scan drives from A: to Z:
// //         for drive_letter in (b'A'..=b'Z').map(|c| c as char) {
// //             let drive_path = format!("{}:\\", drive_letter);
            
// //             log::debug!("Checking drive: {}", drive_path);
            
// //             if self.is_usb_drive(&drive_path) {
// //                 log::info!("✅ Potential USB drive found: {}", drive_path);
                
// //                 if let Some(device_info) = self.get_drive_info(&drive_path) {
// //     // Clone the values before moving device_info into the vector
// //     let drive_letter = device_info.drive_letter.clone();
// //     let volume_name = device_info.volume_name.clone();
    
// //     devices.push(device_info);
// //     log::info!("📝 Added USB device: {} - {}", drive_letter, volume_name);
// // }
// //             }
// //         }
        
// //         log::info!("📊 USB scan complete: Found {} devices", devices.len());
// //         devices
// //     }

// //ho gya 
// pub fn scan_usb_devices(&self) -> Vec<USBDeviceInfo> {
//     let mut devices = Vec::new();
    
//     println!("🔍 Scanning drives D: to Z:...");
    
//     // Simply check drives D: through Z:
//     for drive_letter in (b'D'..=b'Z').map(|c| c as char) {
//         let drive_path = format!("{}:\\", drive_letter);
//         let path = Path::new(&drive_path);
        
//         if path.exists() {
//             println!("✅ Found drive: {}", drive_path);
            
//             // Get REAL volume name and size
//             let (volume_name, total_size) = self.get_real_drive_info(&drive_path);

//             // Create basic device info
//             let device_info = USBDeviceInfo {
//                 drive_letter: drive_path[0..2].to_string(),
//                 volume_name,
//                 // : format!("Drive_{}", drive_letter),
//                 total_size,
//                 // : 16_000_000_000, // 16GB default
//                 free_space: 8_000_000_000,  // 8GB free default
//                 file_system: "USB_DRIVE".to_string(),
//                 serial_number: format!("SN_{}", drive_letter),
//                 insertion_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
//             };
            
//             devices.push(device_info);
//             // println!("   📝 Volume: {}, Size: {} GB", 
//             //         device_info.volume_name, 
//             //         device_info.total_size / 1_000_000_000);
//         } else {
//             println!("❌ Drive not found: {}", drive_path);
//         }
//     }
    
//     println!("📊 Found {} drives total", devices.len());
//     devices
// }

//     /// Get real drive information
// fn get_real_drive_info(&self, drive_path: &str) -> (String, u64) {
//     let mut volume_name = format!("Drive_{}", &drive_path[0..1]);
//     let mut total_size = 16_000_000_000; // Default 16GB
    
//     // Try to get real volume name using Windows command
//     if let Ok(output) = std::process::Command::new("cmd")
//         .args(&["/C", &format!("vol {}", drive_path)])
//         .output() 
//     {
//         let output_str = String::from_utf8_lossy(&output.stdout);
        
//         // Parse volume name from output like: "Volume in drive E is MY_USB"
//         for line in output_str.lines() {
//             if line.contains("Volume in drive") && line.contains("is") {
//                 if let Some(name_start) = line.find("is ") {
//                     let name = line[name_start + 3..].trim();
//                     if !name.is_empty() && name != "has no label" {
//                         volume_name = name.to_string();
//                     }
//                 }
//             }
//         }
//     }
    
//     // Get real drive size
//     if let Ok(metadata) = std::fs::metadata(drive_path) {
//         total_size = metadata.len();
//     }
    
//     (volume_name, total_size)
// }


//     /// Check if a drive is likely a USB drive
//     fn is_usb_drive(&self, drive_path: &str) -> bool {
//         let path = Path::new(drive_path);
        
//         // Basic checks
//         if !path.exists() {
//             return false;
//         }
        
//         // Always exclude system drive C:
//         if drive_path.starts_with("C:") {
//             return false;
//         }
        
//         // Check if it's likely a USB drive using better heuristics
//         if cfg!(target_os = "windows") {
//             self.is_likely_windows_usb(drive_path)
//         } else {
//             // For Linux/Mac, use different logic
//             true // For now, assume any non-C drive is USB on other platforms
//         }
//     }

//     #[cfg(target_os = "windows")]
//     fn is_likely_windows_usb(&self, drive_path: &str) -> bool {
//         use std::process::Command;
        
//         // Method 1: Try to use WMIC to check drive type
//         if let Ok(output) = Command::new("cmd")
//             .args(&["/C", &format!("wmic logicaldisk where DeviceID='{}' get DriveType", &drive_path[0..2])])
//             .output() 
//         {
//             let output_str = String::from_utf8_lossy(&output.stdout);
//             // DriveType 2 = Removable (USB), 3 = Fixed (HDD)
//             if output_str.contains("2") {
//                 return true;
//             }
//         }
        
//         // Method 2: Check if it's a common USB drive letter
//         let common_usb_letters = ["D:", "E:", "F:", "G:", "H:", "I:", "J:", "K:"];
//         if common_usb_letters.contains(&&drive_path[0..2]) {
//             return true;
//         }
        
//         // Method 3: Check if drive has typical USB characteristics
//         // USB drives often have smaller capacity and specific file systems
//         if let Ok(metadata) = std::fs::metadata(drive_path) {
//             let size_gb = metadata.len() / 1_000_000_000;
//             // USB drives are typically between 1GB and 256GB
//             if size_gb >= 1 && size_gb <= 256 {
//                 return true;
//             }
//         }
        
//         // If we can't determine, assume it's USB to be safe
//         true
//     }

//     /// Get information about a drive
//     fn get_drive_info(&self, drive_path: &str) -> Option<USBDeviceInfo> {
//         let metadata = std::fs::metadata(drive_path).ok()?;
        
//         Some(USBDeviceInfo {
//             drive_letter: drive_path[0..2].to_string(),
//             volume_name: self.get_volume_name(&drive_path[0..2]).unwrap_or_else(|| "USB_DRIVE".to_string()),
//             total_size: metadata.len(),
//             free_space: metadata.len() / 2, // Simplified
//             file_system: "FAT32/NTFS".to_string(),
//             serial_number: format!("SN_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
//             insertion_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
//         })
//     }

//     /// Get volume name (simplified)
//     fn get_volume_name(&self, drive_letter: &str) -> Option<String> {
//         // Simplified - in production use Windows API
//         Some(format!("USB_Drive_{}", drive_letter))
//     }

//     /// Analyze files on a USB drive
//     pub fn analyze_usb_files(&self, drive_letter: &str) -> USBFileAnalysis {
//         let mut analysis = USBFileAnalysis {
//             total_files: 0,
//             total_folders: 0,
//             total_size: 0,
//             file_types: HashMap::new(),
//             file_list: Vec::new(),
//             suspicious_files: Vec::new(),
//         };
    
//         let drive_path = format!("{}\\", drive_letter);
        
//         println!("   📁 Scanning files on {}...", drive_letter);
        
//         if let Ok(entries) = std::fs::read_dir(&drive_path) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
                
//                 if path.is_dir() {
//                     analysis.total_folders += 1;
//                 } else if path.is_file() {
//                     analysis.total_files += 1;
                    
//                     // Get file extension
//                     if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
//                         let ext = extension.to_lowercase();
//                         *analysis.file_types.entry(ext).or_insert(0) += 1;
//                     }
                    
//                     // Get file size
//                     if let Ok(metadata) = std::fs::metadata(&path) {
//                         analysis.total_size += metadata.len();
//                     }
                    
//                     // Add filename to list
//                     if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
//                         analysis.file_list.push(file_name.to_string());
//                     }
//                 }
//             }
//         }
        
//         println!("   📊 Found {} files, {} folders", analysis.total_files, analysis.total_folders);
        
//         // Show sample files
//         if !analysis.file_list.is_empty() {
//             println!("   📄 Sample files:");
//             for file in analysis.file_list.iter().take(5) {
//                 println!("     - {}", file);
//             }
//             if analysis.file_list.len() > 5 {
//                 println!("     ... and {} more files", analysis.file_list.len() - 5);
//             }
//         }
        
//         analysis
//     }

//     /// Recursively analyze directory
//     fn analyze_directory(&self, dir_path: &Path, analysis: &mut USBFileAnalysis) {
//         if let Ok(entries) = std::fs::read_dir(dir_path) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
                
//                 if path.is_dir() {
//                     analysis.total_folders += 1;
//                     self.analyze_directory(&path, analysis);
//                 } else if path.is_file() {
//                     self.analyze_file(&path, analysis);
//                 }
//             }
//         }
//     }

//     /// Analyze a single file
//     fn analyze_file(&self, file_path: &Path, analysis: &mut USBFileAnalysis) {
//         analysis.total_files += 1;
        
//         // Get file extension
//         let extension = file_path
//             .extension()
//             .and_then(|ext| ext.to_str())
//             .unwrap_or("no_extension")
//             .to_lowercase();
        
//         // Count file type
//         *analysis.file_types.entry(extension.clone()).or_insert(0) += 1;
        
//         // Get file size
//         if let Ok(metadata) = std::fs::metadata(file_path) {
//             analysis.total_size += metadata.len();
//         }
        
//         // Add to file list
//         if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
//             analysis.file_list.push(file_name.to_string());
//         }
        
//         // Check for suspicious files
//         if self.is_suspicious_file(&extension, file_path) {
//             if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
//                 analysis.suspicious_files.push(file_name.to_string());
//             }
//         }
//     }

//     /// Check if a file is suspicious
//     fn is_suspicious_file(&self, extension: &str, file_path: &Path) -> bool {
//         let suspicious_extensions = [
//             "exe", "bat", "cmd", "ps1", "vbs", "js", "jar", "scr", "pif", "com", "msi"
//         ];
        
//         let suspicious_keywords = [
//             "keygen", "crack", "serial", "patch", "loader", "activator", "torrent", "hack", "exploit"
//         ];
        
//         // Check extension
//         if suspicious_extensions.contains(&extension) {
//             return true;
//         }
        
//         // Check filename for suspicious keywords
//         if let Some(filename) = file_path.file_name().and_then(|name| name.to_str()) {
//             let filename_lower = filename.to_lowercase();
//             for keyword in &suspicious_keywords {
//                 if filename_lower.contains(keyword) {
//                     return true;
//                 }
//             }
//         }
        
//         false
//     }

//     /// Send USB alert to backend
//     // async fn send_usb_alert(
//     //     &self,
//     //     device: &USBDeviceInfo,
//     //     file_analysis: &USBFileAnalysis,
//     //     action: &str,
//     //     communicator: &ServerCommunicator,
//     //     agent_id: u64,
//     //     token: &str
//     // ) -> Result<(), Box<dyn std::error::Error>> {
//     //     let usb_alert = serde_json::json!({
//     //         "agentId": agent_id,
//     //         "alertType": if action == "BLOCKED" { "USB_BLOCKED" } else { "USB_INSERTION" },
//     //         "deviceInfo": {
//     //             "driveLetter": device.drive_letter,
//     //             "volumeName": device.volume_name,
//     //             "totalSize": device.total_size,
//     //             "freeSpace": device.free_space,
//     //             "fileSystem": device.file_system,
//     //             "serialNumber": device.serial_number,
//     //             "insertionTime": device.insertion_time
//     //         },
//     //         "fileAnalysis": {
//     //             "totalFiles": file_analysis.total_files,
//     //             "totalFolders": file_analysis.total_folders,
//     //             "totalSize": file_analysis.total_size,
//     //             "fileTypes": file_analysis.file_types,
//     //             "fileList": file_analysis.file_list,
//     //             "suspiciousFiles": file_analysis.suspicious_files
//     //         },
//     //         "actionTaken": action,
//     //         "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
//     //     });

//     //     communicator.send_usb_alert(&usb_alert, token).await?;
//     //     log::info!("📤 USB alert sent: {} - {} files analyzed", device.drive_letter, file_analysis.total_files);
//     //     Ok(())
//     // }

//     async fn send_usb_alert(
//         &self,
//         device: &USBDeviceInfo,
//         file_analysis: &USBFileAnalysis,
//         action: &str,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         let usb_alert = serde_json::json!({
//             "agentId": agent_id,
//             "alertType": "USB_INSERTION",
//             "description": format!("USB device detected: {} - {} files analyzed", 
//                                   device.drive_letter, file_analysis.total_files),
//             "deviceInfo": format!("Drive: {}, Volume: {}, Size: {}GB", 
//                                  device.drive_letter, device.volume_name, 
//                                  device.total_size / 1_000_000_000),
//             "fileDetails": format!("Files: {}, Folders: {}, Total Size: {}MB, File Types: {:?}", 
//                                   file_analysis.total_files, file_analysis.total_folders,
//                                   file_analysis.total_size / 1_000_000, file_analysis.file_types),
//             "severity": "MEDIUM",
//             "actionTaken": action
//         });
    
//         println!("📤 SENDING USB ALERT TO BACKEND...");
//         println!("URL: /api/agent/alerts");
//         println!("Data: {}", usb_alert);
    
//         // Send to the correct endpoint
//         match communicator.send_alert(&usb_alert, token).await {
//             Ok(_) => {
//                 println!("✅ USB alert sent successfully to backend!");
//                 Ok(())
//             }
//             Err(e) => {
//                 println!("❌ Failed to send USB alert: {}", e);
//                 Err(e)
//             }
//         }
//     }

// }

// // ===== PROTECTION MODULE IMPLEMENTATION =====

// #[async_trait::async_trait]
// impl ProtectionModule for USBProtection {
//     /// Execute USB protection based on active policies
//     async fn execute(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         // Only run if USB protection is enabled
//         if policy_engine.is_usb_protection_enabled() {
//             self.execute_monitoring(policy_engine, communicator, agent_id, token).await?;
//         }
//         Ok(())
//     }
   
//     /// Get module name
//     fn get_name(&self) -> &str {
//         "USB"
//     }
// }
// // protection_modules/usb_protection.rs
// // USB device and file protection implementation

// // use crate::policy_engine::PolicyEngine;
// // use crate::communication::ServerCommunicator;
// // use crate::protection_modules::ProtectionModule;
// // use crate::policy_constants::*;
// // use serde::{Deserialize, Serialize};
// // use std::collections::{HashMap, HashSet};
// // use std::time::{SystemTime, UNIX_EPOCH};
// // use std::path::{Path, PathBuf};
// // use std::fs;
// // use log::{info, warn, error, debug};

// // // ===== DATA STRUCTURES =====

// // /// Information about a USB device
// // #[derive(Debug, Clone, Serialize, Deserialize)]
// // pub struct USBDeviceInfo {
// //     pub drive_letter: String, // e.g. "F:"
// //     pub volume_name: String,
// //     pub total_size: u64,
// //     pub free_space: u64,
// //     pub file_system: String,
// //     pub serial_number: String,
// //     pub insertion_time: u64,
// // }

// // /// Analysis results of files on a USB device
// // #[derive(Debug, Clone, Serialize, Deserialize)]
// // pub struct USBFileAnalysis {
// //     pub total_files: usize,
// //     pub total_folders: usize,
// //     pub total_size: u64,
// //     pub file_types: HashMap<String, usize>,
// //     pub file_list: Vec<String>,
// //     pub suspicious_files: Vec<String>,
// // }

// // // ===== USB PROTECTION MODULE =====

// // /// USB protection module that monitors and controls USB devices
// // pub struct USBProtection {
// //     known_devices: HashSet<String>, // Track known USB devices (drive letters like "F:")
// //     known_files: HashSet<String>,   // Track files we've already seen (full path strings)
// //     last_scan_time: u64,            // Last scan time for rate limiting (epoch seconds)
// // }

// // impl USBProtection {
// //     /// Create a new USB protection module
// //     pub fn new() -> Self {
// //         Self {
// //             known_devices: HashSet::new(),
// //             known_files: HashSet::new(),
// //             last_scan_time: 0,
// //         }
// //     }

// //     fn get_communicator_for_alert(&self) -> ServerCommunicator {
// //         // Create a fresh communicator for alerts if needed.
// //         ServerCommunicator::new()
// //     }

// //     /// Main monitoring logic for USB devices
// //     async fn execute_monitoring(
// //         &mut self,
// //         policy_engine: &PolicyEngine,
// //         communicator: &ServerCommunicator,
// //         agent_id: u64,
// //         token: &str
// //     ) -> Result<(), Box<dyn std::error::Error>> {
// //         let current_devices = self.scan_usb_devices();

// //         // Detect new USB devices
// //         for device in &current_devices {
// //             if !self.known_devices.contains(&device.drive_letter) {
// //                 info!("🎯 New USB device detected: {}", device.drive_letter);

// //                 // Check specific policies for this device
// //                 if policy_engine.should_block_usb_devices() {
// //                     warn!("🚫 USB BLOCKED by {} policy: {}", POLICY_USB_DEVICE_BLOCK, device.drive_letter);
// //                     self.handle_blocked_usb(device, communicator, agent_id, token).await?;
// //                 } else if policy_engine.should_monitor_usb_devices() {
// //                     info!("👀 USB MONITORING by {} policy: {}", POLICY_USB_DEVICE_MONITOR, device.drive_letter);

// //                     // Analyze files
// //                     let file_analysis = self.analyze_usb_files(&device.drive_letter);
// //                     self.send_usb_alert(device, &file_analysis, "MONITORED", communicator, agent_id, token).await?;

// //                     // Optionally monitor file operations (single scan pass)
// //                     if policy_engine.should_block_executable_files() || policy_engine.should_detect_suspicious_files() {
// //                         self.monitor_file_operations(&device.drive_letter, policy_engine, communicator, agent_id, token).await?;
// //                     }
// //                 }

// //                 // Mark as known
// //                 self.known_devices.insert(device.drive_letter.clone());
// //             }
// //         }

// //         // Detect removed USB devices
// //         let current_drives: HashSet<String> = current_devices.iter()
// //             .map(|d| d.drive_letter.clone())
// //             .collect();

// //         let removed: Vec<String> = self.known_devices.difference(&current_drives).cloned().collect();
// //         for rem in removed {
// //             info!("📤 USB device removed: {}", rem);
// //             // cleanup known files that belonged to removed drive
// //             self.known_files.retain(|p| !p.to_lowercase().starts_with(&rem.to_lowercase()));
// //         }

// //         // Update known devices and scan time
// //         self.known_devices = current_drives;
// //         self.last_scan_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

// //         Ok(())
// //     }

// //     /// Handle a USB device that should be blocked
// //     async fn handle_blocked_usb(
// //         &self,
// //         device: &USBDeviceInfo,
// //         communicator: &ServerCommunicator,
// //         agent_id: u64,
// //         token: &str
// //     ) -> Result<(), Box<dyn std::error::Error>> {
// //         // Create empty file analysis for blocked device
// //         let file_analysis = USBFileAnalysis {
// //             total_files: 0,
// //             total_folders: 0,
// //             total_size: 0,
// //             file_types: HashMap::new(),
// //             file_list: Vec::new(),
// //             suspicious_files: Vec::new(),
// //         };

// //         // Send block alert to backend
// //         self.send_usb_alert(device, &file_analysis, "BLOCKED", communicator, agent_id, token).await?;

// //         // NOTE: Programmatic ejection and access prevention require platform APIs and privileges.
// //         warn!("🛑 USB device {} has been blocked by DLP policy", device.drive_letter);

// //         Ok(())
// //     }

// //     /// Monitor file operations on a USB drive (single scan pass)
// //     async fn monitor_file_operations(
// //         &mut self,
// //         drive_letter: &str,
// //         policy_engine: &PolicyEngine,
// //         communicator: &ServerCommunicator,
// //         agent_id: u64,
// //         token: &str
// //     ) -> Result<(), Box<dyn std::error::Error>> {
// //         let drive_path = format!("{}\\", drive_letter); // "F:\\" or "F:\"
// //         let current_files = match Self::scan_files(&drive_path) {
// //             Ok(files) => files,
// //             Err(_) => {
// //                 warn!("⚠️ Cannot scan files on drive {} - may be disconnected", drive_letter);
// //                 return Ok(());
// //             }
// //         };

// //         // Determine new files
// //         let new_files: Vec<String> = current_files.iter()
// //             .filter(|fp| !self.known_files.contains(*fp))
// //             .cloned()
// //             .collect();

// //         if !new_files.is_empty() {
// //             info!("📄 Found {} new files on USB drive {}", new_files.len(), drive_letter);

// //             for file_path in &new_files {
// //                 // Check for executable blocking
// //                 if policy_engine.should_block_executable_files() {
// //                     if let Some(ext) = Path::new(file_path).extension().and_then(|e| e.to_str()) {
// //                         let ext_lower = ext.to_lowercase();
// //                         let executable_extensions = ["exe", "bat", "msi", "ps1", "cmd", "com"];

// //                         if executable_extensions.contains(&ext_lower.as_str()) {
// //                             warn!("🚫 Executable file BLOCKED by {} policy: {} (extension: {})",
// //                                   POLICY_USB_BLOCK_EXECUTABLES, file_path, ext_lower);

// //                             // try to remove (best-effort)
// //                             if let Err(e) = fs::remove_file(file_path) {
// //                                 error!("❌ Failed to remove blocked file {}: {}", file_path, e);
// //                             } else {
// //                                 info!("✅ Blocked executable file removed: {}", file_path);
// //                                 Self::send_file_block_alert(
// //                                     communicator,
// //                                     agent_id,
// //                                     token,
// //                                     file_path,
// //                                     &ext_lower,
// //                                     POLICY_USB_BLOCK_EXECUTABLES
// //                                 ).await?;
// //                             }

// //                             // don't continue other checks for this file
// //                             continue;
// //                         }
// //                     }
// //                 }

// //                 // Check for suspicious files
// //                 if policy_engine.should_detect_suspicious_files() {
// //                     if let Some(ext) = Path::new(file_path).extension().and_then(|e| e.to_str()) {
// //                         let ext_lower = ext.to_lowercase();
// //                         if self.is_suspicious_file(&ext_lower, Path::new(file_path)) {
// //                             warn!("⚠️ Suspicious file detected by {} policy: {}", POLICY_USB_DETECT_SUSPICIOUS, file_path);

// //                             Self::send_suspicious_file_alert(
// //                                 communicator,
// //                                 agent_id,
// //                                 token,
// //                                 file_path
// //                             ).await?;
// //                         }
// //                     }
// //                 }
// //             }

// //             // Update known files set
// //             self.known_files.extend(new_files);
// //         }

// //         Ok(())
// //     }

// //     // ===== UTILITY METHODS =====

// //     /// Scan files in a directory (top-level only)
// //     fn scan_files(drive_path: &str) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
// //         let mut files = HashSet::new();

// //         if let Ok(entries) = fs::read_dir(drive_path) {
// //             for entry in entries.flatten() {
// //                 let path = entry.path();
// //                 if path.is_file() {
// //                     if let Some(path_str) = path.to_str() {
// //                         files.insert(path_str.to_string());
// //                     } else {
// //                         debug!("Skipped non-UTF8 path in {}", drive_path);
// //                     }
// //                 }
// //             }
// //         }

// //         Ok(files)
// //     }

// //     /// Send file block alert to backend
// //     async fn send_file_block_alert(
// //         communicator: &ServerCommunicator,
// //         agent_id: u64,
// //         token: &str,
// //         file_path: &str,
// //         file_extension: &str,
// //         policy_code: &str
// //     ) -> Result<(), Box<dyn std::error::Error>> {
// //         let alert_data = serde_json::json!({
// //             "agentId": agent_id,
// //             "alertType": "FILE_BLOCKED",
// //             "description": format!("File blocked by {} policy: {} (Extension: {})", policy_code, file_path, file_extension),
// //             "deviceInfo": "USB Device",
// //             "fileDetails": format!("Blocked file: {}, Extension: {}, Policy: {}", file_path, file_extension, policy_code),
// //             "severity": "HIGH",
// //             "actionTaken": "BLOCKED",
// //             "policyCode": policy_code
// //         });

// //         communicator.send_alert(&alert_data, token).await?;
// //         info!("📤 Sent file block alert for: {} (Policy: {})", file_path, policy_code);
// //         Ok(())
// //     }

// //     /// Send suspicious file alert to backend
// //     async fn send_suspicious_file_alert(
// //         communicator: &ServerCommunicator,
// //         agent_id: u64,
// //         token: &str,
// //         file_path: &str
// //     ) -> Result<(), Box<dyn std::error::Error>> {
// //         let alert_data = serde_json::json!({
// //             "agentId": agent_id,
// //             "alertType": "SUSPICIOUS_FILE_DETECTED",
// //             "description": format!("Suspicious file detected on USB: {}", file_path),
// //             "deviceInfo": "USB Device",
// //             "fileDetails": format!("Suspicious file: {}", file_path),
// //             "severity": "MEDIUM",
// //             "actionTaken": "DETECTED",
// //             "policyCode": POLICY_USB_DETECT_SUSPICIOUS
// //         });

// //         communicator.send_alert(&alert_data, token).await?;
// //         info!("📤 Sent suspicious file alert for: {}", file_path);
// //         Ok(())
// //     }

// //     /// Scan for USB devices on the system
// //     pub fn scan_usb_devices(&self) -> Vec<USBDeviceInfo> {
// //         let mut devices = Vec::new();

// //         for letter in b'A'..=b'Z' {
// //             let drive_letter = (letter as char).to_string() + ":"; // e.g. "F:"
// //             let drive_path = format!("{}\\", drive_letter); // "F:\\" (Windows)
// //             if self.is_usb_drive(&drive_path) {
// //                 if let Some(info) = self.get_drive_info(&drive_path) {
// //                     devices.push(info);
// //                 }
// //             }
// //         }

// //         devices
// //     }

// //     /// Check if a drive is likely a USB drive
// //     fn is_usb_drive(&self, drive_path: &str) -> bool {
// //         let p = Path::new(drive_path);
// //         if !p.exists() {
// //             return false;
// //         }

// //         // Extract drive letter e.g. "F:"
// //         if let Some(first_char) = drive_path.chars().next() {
// //             let drive_letter = first_char.to_ascii_uppercase();
// //             // Exclude common system drives by letter. Adjust per environment.
// //             if drive_letter == 'C' || drive_letter == 'D' || drive_letter == 'E' {
// //                 return false;
// //             }
// //             // Heuristic: if it exists and not excluded, treat as removable for now.
// //             return true;
// //         }

// //         false
// //     }

// //     /// Get information about a drive
// //     fn get_drive_info(&self, drive_path: &str) -> Option<USBDeviceInfo> {
// //         // drive_path expected like "F:\\"
// //         let path = Path::new(drive_path);
// //         if !path.exists() {
// //             return None;
// //         }

// //         // drive_letter string "F:"
// //         let drive_letter = drive_path.chars().next().map(|c| format!("{}:", c)).unwrap_or_else(|| "?:".to_string());

// //         // root metadata: may not give total size; attempt file listing for an estimate
// //         let mut total_size: u64 = 0;
// //         if let Ok(entries) = fs::read_dir(path) {
// //             for entry in entries.flatten() {
// //                 if let Ok(meta) = entry.metadata() {
// //                     if meta.is_file() {
// //                         total_size = total_size.saturating_add(meta.len());
// //                     }
// //                 }
// //             }
// //         }

// //         Some(USBDeviceInfo {
// //             drive_letter: drive_letter.clone(),
// //             volume_name: self.get_volume_name(&drive_letter).unwrap_or_else(|| "USB_DRIVE".to_string()),
// //             total_size,
// //             free_space: total_size / 2, // fallback heuristic
// //             file_system: "FAT32/NTFS".to_string(),
// //             serial_number: format!("SN_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
// //             insertion_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
// //         })
// //     }

// //     /// Get volume name (simplified)
// //     fn get_volume_name(&self, drive_letter: &str) -> Option<String> {
// //         Some(format!("USB_Drive_{}", drive_letter.trim_end_matches(':')))
// //     }

// //     /// Analyze files on a USB drive (recursive)
// //     pub fn analyze_usb_files(&self, drive_letter: &str) -> USBFileAnalysis {
// //         let mut analysis = USBFileAnalysis {
// //             total_files: 0,
// //             total_folders: 0,
// //             total_size: 0,
// //             file_types: HashMap::new(),
// //             file_list: Vec::new(),
// //             suspicious_files: Vec::new(),
// //         };

// //         let drive_path = format!("{}\\", drive_letter);
// //         let root = Path::new(&drive_path);

// //         if let Ok(entries) = fs::read_dir(root) {
// //             for entry in entries.flatten() {
// //                 let path = entry.path();
// //                 if path.is_dir() {
// //                     analysis.total_folders += 1;
// //                     self.analyze_directory(&path, &mut analysis);
// //                 } else if path.is_file() {
// //                     self.analyze_file(&path, &mut analysis);
// //                 }
// //             }
// //         }

// //         analysis
// //     }

// //     /// Recursively analyze directory
// //     fn analyze_directory(&self, dir_path: &Path, analysis: &mut USBFileAnalysis) {
// //         if let Ok(entries) = fs::read_dir(dir_path) {
// //             for entry in entries.flatten() {
// //                 let path = entry.path();
// //                 if path.is_dir() {
// //                     analysis.total_folders += 1;
// //                     self.analyze_directory(&path, analysis);
// //                 } else if path.is_file() {
// //                     self.analyze_file(&path, analysis);
// //                 }
// //             }
// //         }
// //     }

// //     /// Analyze a single file
// //     fn analyze_file(&self, file_path: &Path, analysis: &mut USBFileAnalysis) {
// //         analysis.total_files = analysis.total_files.saturating_add(1);

// //         // Get file extension
// //         let extension = file_path
// //             .extension()
// //             .and_then(|ext| ext.to_str())
// //             .unwrap_or("no_extension")
// //             .to_lowercase();

// //         *analysis.file_types.entry(extension.clone()).or_insert(0) += 1;

// //         // Get file size
// //         if let Ok(metadata) = fs::metadata(file_path) {
// //             analysis.total_size = analysis.total_size.saturating_add(metadata.len());
// //         }

// //         // Add to file list if possible
// //         if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
// //             analysis.file_list.push(file_name.to_string());
// //         }

// //         // Check for suspicious files
// //         if self.is_suspicious_file(&extension, file_path) {
// //             if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
// //                 analysis.suspicious_files.push(file_name.to_string());
// //             }
// //         }
// //     }

// //     /// Check if a file is suspicious
// //     fn is_suspicious_file(&self, extension: &str, file_path: &Path) -> bool {
// //         let suspicious_extensions = [
// //             "exe", "bat", "cmd", "ps1", "vbs", "js", "jar", "scr", "pif", "com", "msi"
// //         ];

// //         let suspicious_keywords = [
// //             "keygen", "crack", "serial", "patch", "loader", "activator", "torrent", "hack", "exploit"
// //         ];

// //         if suspicious_extensions.contains(&extension) {
// //             return true;
// //         }

// //         if let Some(filename) = file_path.file_name().and_then(|name| name.to_str()) {
// //             let filename_lower = filename.to_lowercase();
// //             for keyword in &suspicious_keywords {
// //                 if filename_lower.contains(keyword) {
// //                     return true;
// //                 }
// //             }
// //         }

// //         false
// //     }

// //     /// Send USB alert to backend
// //     async fn send_usb_alert(
// //         &self,
// //         device: &USBDeviceInfo,
// //         file_analysis: &USBFileAnalysis,
// //         action: &str,
// //         communicator: &ServerCommunicator,
// //         agent_id: u64,
// //         token: &str
// //     ) -> Result<(), Box<dyn std::error::Error>> {
// //         let usb_alert = serde_json::json!({
// //             "agentId": agent_id,
// //             "alertType": if action == "BLOCKED" { "USB_BLOCKED" } else { "USB_INSERTION" },
// //             "deviceInfo": {
// //                 "driveLetter": device.drive_letter,
// //                 "volumeName": device.volume_name,
// //                 "totalSize": device.total_size,
// //                 "freeSpace": device.free_space,
// //                 "fileSystem": device.file_system,
// //                 "serialNumber": device.serial_number,
// //                 "insertionTime": device.insertion_time
// //             },
// //             "fileAnalysis": {
// //                 "totalFiles": file_analysis.total_files,
// //                 "totalFolders": file_analysis.total_folders,
// //                 "totalSize": file_analysis.total_size,
// //                 "fileTypes": file_analysis.file_types,
// //                 "fileList": file_analysis.file_list,
// //                 "suspiciousFiles": file_analysis.suspicious_files
// //             },
// //             "actionTaken": action,
// //             "timestamp": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
// //         });

// //         communicator.send_usb_alert(&usb_alert, token).await?;
// //         info!("📤 USB alert sent: {} - {} files analyzed", device.drive_letter, file_analysis.total_files);
// //         Ok(())
// //     }
// // }

// // // ===== PROTECTION MODULE IMPLEMENTATION =====

// // #[async_trait::async_trait]
// // impl ProtectionModule for USBProtection {
// //     /// Execute USB protection based on active policies
// //     async fn execute(
// //         &mut self,
// //         policy_engine: &PolicyEngine,
// //         communicator: &ServerCommunicator,
// //         agent_id: u64,
// //         token: &str
// //     ) -> Result<(), Box<dyn std::error::Error>> {
// //         // Only run if USB protection is enabled
// //         if policy_engine.is_usb_protection_enabled() {
// //             self.execute_monitoring(policy_engine, communicator, agent_id, token).await?;
// //         }
// //         Ok(())
// //     }

// //     /// Get module name
// //     fn get_name(&self) -> &str {
// //         "USB"
// //     }
// // }







// use crate::policy_engine::PolicyEngine;
// use crate::communication::ServerCommunicator;
// use crate::protection_modules::ProtectionModule;
// use crate::policy_constants::*;
// use serde::{Deserialize, Serialize};
// use std::collections::{HashMap, HashSet};
// use std::time::{SystemTime, UNIX_EPOCH};
// use std::path::{Path, PathBuf};
// use std::ffi::OsString;
// use std::os::windows::ffi::OsStringExt;
// use std::fs;
// use log::{info, warn, error, debug};
// use tokio::time;
// use std::ptr;

// use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
// use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
// use windows_sys::Win32::System::IO::{CreateFileW, DeviceIoControl, GENERIC_READ};
// use windows_sys::Win32::System::Ioctl::IOCTL_STORAGE_EJECT_MEDIA;
// use windows_sys::Win32::System::SystemServices::{GetDriveTypeW, GetLogicalDrives};

// // ===== DATA STRUCTURES =====

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct USBDeviceInfo {
//     pub drive_letter: String,
//     pub volume_name: String,
//     pub total_size: u64,
//     pub free_space: u64,
//     pub file_system: String,
//     pub serial_number: String,
//     pub insertion_time: u64,
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct USBFileAnalysis {
//     pub total_files: usize,
//     pub total_folders: usize,
//     pub total_size: u64,
//     pub file_types: HashMap<String, usize>,
//     pub file_list: Vec<String>,
//     pub suspicious_files: Vec<String>,
// }

// impl USBFileAnalysis {
//     fn empty() -> Self {
//         Self {
//             total_files: 0,
//             total_folders: 0,
//             total_size: 0,
//             file_types: HashMap::new(),
//             file_list: Vec::new(),
//             suspicious_files: Vec::new(),
//         }
//     }
// }

// // ===== USB PROTECTION MODULE =====

// pub struct USBProtection {
//     known_devices: HashSet<String>,
//     known_files: HashSet<String>,
//     last_scan_time: u64,
// }

// impl USBProtection {
//     pub fn new() -> Self {
//         Self {
//             known_devices: HashSet::new(),
//             known_files: HashSet::new(),
//             last_scan_time: 0,
//         }
//     }

//     async fn execute_monitoring(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         let current_devices = self.scan_usb_devices();

//         for device in &current_devices {
//             if !self.known_devices.contains(&device.drive_letter) {
//                 info!("🎯 New USB device detected: {}", device.drive_letter);
//                 self.known_devices.insert(device.drive_letter.clone());

//                 if policy_engine.is_policy_active(POLICY_USB_DEVICE_BLOCK) {
//                     warn!("🚫 USB BLOCKED by policy: {}", device.drive_letter);
//                     self.handle_blocked_usb(device, communicator, agent_id, token).await?;
//                     continue;
//                 }

//                 if policy_engine.is_policy_active(POLICY_USB_DEVICE_MONITOR) {
//                     info!("👀 USB CONNECTION MONITORED: {}", device.drive_letter);
//                     self.send_usb_alert(device, &USBFileAnalysis::empty(), "MONITORED", communicator, agent_id, token).await?;
//                 }

//                 if policy_engine.is_policy_active(POLICY_USB_SCAN_FILES) {
//                     info!(" SCANNING FILES on USB: {}", device.drive_letter);
//                     let file_analysis = self.analyze_usb_files(&device.drive_letter);
//                     self.send_usb_alert(device, &file_analysis, "SCANNED", communicator, agent_id, token).await?;
//                 }

//                 if policy_engine.is_policy_active(POLICY_USB_BLOCK_EXECUTABLES) ||
//                    policy_engine.is_policy_active(POLICY_USB_DETECT_SUSPICIOUS) {
//                     self.monitor_file_operations(&device.drive_letter, policy_engine, communicator, agent_id, token).await?;
//                 }
//             }
//         }

//         let current_drives: HashSet<String> = current_devices.iter().map(|d| d.drive_letter.clone()).collect();
//         self.known_devices.retain(|known_drive| {
//             let is_still_connected = current_drives.contains(known_drive);
//             if !is_still_connected {
//                 info!("📤 USB device removed: {}", known_drive);
//             }
//             is_still_connected
//         });

//         self.last_scan_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
//         Ok(())
//     }

//     async fn handle_blocked_usb(
//         &self,
//         device: &USBDeviceInfo,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         warn!("🛑 USB device {} has been blocked by DLP policy. Ejection should be implemented.", device.drive_letter);
//         self.send_usb_alert(device, &USBFileAnalysis::empty(), "BLOCKED", communicator, agent_id, token).await?;

//         let volume_path_str = format!(r"\\.\{}", device.drive_letter);
//         let mut volume_path_w: Vec<u16> = volume_path_str.encode_utf16().collect();
//         volume_path_w.push(0);

//         unsafe {
//             let handle = CreateFileW(
//                 volume_path_w.as_ptr(),
//                 GENERIC_READ,
//                 FILE_SHARE_READ | FILE_SHARE_WRITE,
//                 ptr::null_mut(),
//                 OPEN_EXISTING,
//                 0,
//                 0,
//             );

//             if handle == INVALID_HANDLE_VALUE {
//                 error!("Failed to get handle for drive {}. Cannot eject.", device.drive_letter);
//                 return Ok(());
//             }

//             let mut bytes_returned: u32 = 0;
//             let result = DeviceIoControl(
//                 handle,
//                 IOCTL_STORAGE_EJECT_MEDIA,
//                 std::ptr::null(),
//                 0,
//                 std::ptr::null_mut(),
//                 0,
//                 &mut bytes_returned,
//                 std::ptr::null_mut(),
//             );

//             if result == 0 {
//                 error!("Failed to send eject command to {}. The drive may be in use.", device.drive_letter);
//             } else {
//                 info!("✅ Successfully ejected device {}", device.drive_letter);
//             }

//             CloseHandle(handle);
//         }

//         Ok(())
//     }

//     async fn monitor_file_operations(
//         &mut self,
//         drive_letter: &str,
//         policy_engine: &PolicyEngine,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         let drive_path = format!("{}\\", drive_letter);
//         let current_files = match Self::scan_files(&drive_path) {
//             Ok(files) => files,
//             Err(e) => {
//                 warn!("⚠️ Cannot scan files on drive {}: {}", drive_letter, e);
//                 return Ok(());
//             }
//         };

//         let new_files: Vec<String> = current_files.iter()
//             .filter(|file_path| !self.known_files.contains(*file_path))
//             .cloned()
//             .collect();

//         if !new_files.is_empty() {
//             info!("📄 Found {} new files on USB drive {}", new_files.len(), drive_letter);

//             for file_path in &new_files {
//                 let path = Path::new(file_path);

//                 if policy_engine.is_policy_active(POLICY_USB_BLOCK_EXECUTABLES) {
//                     if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
//                         let ext_lower = ext.to_lowercase();
//                         let executable_extensions = ["exe", "bat", "msi", "ps1", "cmd", "com", "scr", "vbs"];
//                         if executable_extensions.contains(&ext_lower.as_str()) {
//                             warn!("🚫 Executable file BLOCKED by policy: {}", file_path);

//                             if let Err(e) = fs::remove_file(file_path) {
//                                 error!("❌ Failed to remove blocked file {}: {}", file_path, e);
//                             } else {
//                                 info!("✅ Blocked executable file removed: {}", file_path);
//                                 Self::send_file_block_alert(communicator, agent_id, token, file_path, &ext_lower, POLICY_USB_BLOCK_EXECUTABLES).await?;
//                             }
//                             continue;
//                         }
//                     }
//                 }

//                 if policy_engine.is_policy_active(POLICY_USB_DETECT_SUSPICIOUS) {
//                     if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
//                         if self.is_suspicious_file(&ext.to_lowercase(), path) {
//                             warn!("⚠️ Suspicious file detected by policy: {}", file_path);
//                             Self::send_suspicious_file_alert(communicator, agent_id, token, file_path).await?;
//                         }
//                     }
//                 }
//             }

//             self.known_files.extend(new_files);
//         }

//         Ok(())
//     }

//     pub fn scan_usb_devices(&self) -> Vec<USBDeviceInfo> {
//         info!("🔍 Scanning for removable USB drives...");
//         let mut devices = Vec::new();
//         let drive_mask = unsafe { GetLogicalDrives() };

//         for i in 0..26 {
//             if (drive_mask >> i) & 1 == 1 {
//                 let drive_letter = (b'A' + i) as char;
//                 let drive_path_str = format!("{}:\\", drive_letter);

//                 if self.is_removable_drive(&drive_path_str) {
//                     info!("✅ Found removable drive: {}", drive_path_str);
//                     if let Some(device_info) = self.get_drive_info(&drive_path_str) {
//                         devices.push(device_info);
//                     }
//                 } else {
//                     debug!("  Ignoring non-removable drive: {}", drive_path_str);
//                 }
//             }
//         }

//         info!("📊 Scan complete. Found {} removable drives.", devices.len());
//         devices
//     }

//     fn is_removable_drive(&self, drive_path: &str) -> bool {
//         let mut path_w: Vec<u16> = drive_path.encode_utf16().collect();
//         path_w.push(0);
//         let drive_type = unsafe { GetDriveTypeW(path_w.as_ptr()) };
//         drive_type == 2
//     }

//     fn get_drive_info(&self, drive_path: &str) -> Option<USBDeviceInfo> {
//         let drive_letter = drive_path[0..2].to_string();
//         let (volume_name, total_size) = self.get_real_drive_info_prototype(drive_path);

//         Some(USBDeviceInfo {
//             drive_letter,
//             volume_name,
//             total_size,
//             free_space: 0,
//             file_system: "Unknown".to_string(),
//             serial_number: "Unknown".to_string(),
//             insertion_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
//         })
//     }

//     fn get_real_drive_info_prototype(&self, drive_path: &str) -> (String, u64) {
//         let mut volume_name = format!("Drive_{}", &drive_path[0..1]);
//         let mut total_size = 0;

//         if let Ok(output) = std::process::Command::new("cmd")
//             .args(&["/C", &format!("vol {}", drive_path)])
//             .output() {
//             let output_str = String::from_utf8_lossy(&output.stdout);
//             for line in output_str.lines() {
//                 if line.contains("Volume in drive") && line.contains("is") {
//                     if let Some(name_start) = line.find("is ") {
//                         let name = line[name_start + 3..].trim();
//                         if !name.is_empty() && name != "has no label" {
//                             volume_name = name.to_string();
//                         }
//                     }
//                 }
//             }
//         }

//         if let Ok(metadata) = fs::metadata(drive_path) {
//             total_size = metadata.len();
//         }

//         (volume_name, total_size)
//     }

//     fn scan_files(drive_path: &str) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
//         let mut files = HashSet::new();
//         if let Ok(entries) = fs::read_dir(drive_path) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
//                 if path.is_file() {
//                     if let Some(path_str) = path.to_str() {
//                         files.insert(path_str.to_string());
//                     }
//                 }
//             }
//         }
//         Ok(files)
//     }

//     pub fn analyze_usb_files(&self, drive_letter: &str) -> USBFileAnalysis {
//         let mut analysis = USBFileAnalysis::empty();
//         let drive_path = format!("{}\\", drive_letter);
//         info!("   📁 Scanning all files and folders on {}...", drive_letter);
//         self.analyze_directory(Path::new(&drive_path), &mut analysis);
//         info!("   📊 Scan complete: Found {} files, {} folders", analysis.total_files, analysis.total_folders);
//         analysis
//     }

//     fn analyze_directory(&self, dir_path: &Path, analysis: &mut USBFileAnalysis) {
//         if let Ok(entries) = fs::read_dir(dir_path) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
//                 if path.is_dir() {
//                     analysis.total_folders += 1;
//                     self.analyze_directory(&path, analysis);
//                 } else if path.is_file() {
//                     self.analyze_file(&path, analysis);
//                 }
//             }
//         }
//     }

//     fn analyze_file(&self, file_path: &Path, analysis: &mut USBFileAnalysis) {
//         analysis.total_files += 1;

//         let extension = file_path.extension()
//             .and_then(|ext| ext.to_str())
//             .unwrap_or("no_extension")
//             .to_lowercase();

//         *analysis.file_types.entry(extension.clone()).or_insert(0) += 1;

//         if let Ok(metadata) = fs::metadata(file_path) {
//             analysis.total_size += metadata.len();
//         }

//         if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
//             analysis.file_list.push(file_name.to_string());
//         }

//         if self.is_suspicious_file(&extension, file_path) {
//             if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
//                 analysis.suspicious_files.push(file_name.to_string());
//             }
//         }
//     }

//     fn is_suspicious_file(&self, extension: &str, file_path: &Path) -> bool {
//         let suspicious_extensions = [
//             "exe", "bat", "cmd", "ps1", "vbs", "js", "jar", "scr", "pif", "com", "msi"
//         ];
//         let suspicious_keywords = [
//             "keygen", "crack", "serial", "patch", "loader", "activator", "torrent", "hack", "exploit"
//         ];

//         if suspicious_extensions.contains(&extension) {
//             return true;
//         }

//         if let Some(filename) = file_path.file_name().and_then(|name| name.to_str()) {
//             let filename_lower = filename.to_lowercase();
//             for keyword in &suspicious_keywords {
//                 if filename_lower.contains(keyword) {
//                     return true;
//                 }
//             }
//         }
//         false
//     }

//     async fn send_usb_alert(
//         &self,
//         device: &USBDeviceInfo,
//         file_analysis: &USBFileAnalysis,
//         action: &str,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         let alert_data = serde_json::json!({
//             "agentId": agent_id,
//             "alertType": if action == "BLOCKED" { "USB_BLOCKED" } else { "USB_INSERTION" },
//             "description": format!("USB device detected: {}. Action: {}.", device.drive_letter, action),
//             "deviceInfo": format!("Drive: {}, Volume: {}, Size: {}GB", 
//                                  device.drive_letter, device.volume_name, 
//                                  device.total_size / 1_000_000_000),
//             "fileDetails": format!("Files: {}, Folders: {}, Total Size: {}MB, Suspicious: {}", 
//                                   file_analysis.total_files, file_analysis.total_folders,
//                                   file_analysis.total_size / 1_000_000, file_analysis.suspicious_files.len()),
//             "severity": if action == "BLOCKED" { "HIGH" } else { "MEDIUM" },
//             "actionTaken": action
//         });

//         info!("📤 Sending USB alert to backend...");
//         communicator.send_alert(&alert_data, token).await
//     }

//     async fn send_file_block_alert(
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//         file_path: &str,
//         file_extension: &str,
//         policy_code: &str,
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         let alert_data = serde_json::json!({
//             "agentId": agent_id,
//             "alertType": "FILE_BLOCKED",
//             "description": format!("Executable file blocked by policy: {}", file_path),
//             "deviceInfo": "USB Device",
//             "fileDetails": format!("File: {}, Extension: {}, Policy: {}", file_path, file_extension, policy_code),
//             "severity": "HIGH",
//             "actionTaken": "BLOCKED"
//         });
//         communicator.send_alert(&alert_data, token).await
//     }

//     async fn send_suspicious_file_alert(
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//         file_path: &str,
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         let alert_data = serde_json::json!({
//             "agentId": agent_id,
//             "alertType": "SUSPICIOUS_FILE_DETECTED",
//             "description": format!("Suspicious file detected on USB: {}", file_path),
//             "deviceInfo": "USB Device", 
//             "fileDetails": format!("File: {}", file_path),
//             "severity": "MEDIUM",
//             "actionTaken": "DETECTED"
//         });
//         communicator.send_alert(&alert_data, token).await
//     }
// }

// #[async_trait::async_trait]
// impl ProtectionModule for USBProtection {
//     async fn execute(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         if policy_engine.is_usb_protection_enabled() {
//             self.execute_monitoring(policy_engine, communicator, agent_id, token).await?;
//         }
//         Ok(())
//     }

//     fn get_name(&self) -> &str {
//         "USB"
//     }
// }
use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;
use crate::protection_modules::ProtectionModule;
use crate::policy_constants::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::{Path, PathBuf};
// use std::ffi::OsString;
// use std::os::windows::ffi::OsStringExt;
use std::fs;
use log::{info, warn, error, debug};
// use tokio::time;

// --- CORRECTED WINDOWS API IMPORTS ---
// --- CORRECTED WINDOWS API IMPORTS ---
use windows_sys::Win32::Foundation::{
    CloseHandle,
    GENERIC_READ,
    // MAX_PATH, // <-- Unused, removed
    INVALID_HANDLE_VALUE,
    // DRIVE_REMOVABLE // <-- Moved back to Foundation
};
use windows_sys::Win32::Storage::FileSystem::{
    GetLogicalDrives,
    GetDriveTypeW,
    CreateFileW,
    OPEN_EXISTING,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE // <-- Moved to FileSystem
};
// 'use windows_sys::Win32::System::SystemServices' is no longer needed
use windows_sys::Win32::System::Ioctl::IOCTL_STORAGE_EJECT_MEDIA;
use windows_sys::Win32::System::IO::DeviceIoControl;
// --- END OF IMPORTS ---
/// Information about a USB device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct USBDeviceInfo {
    pub drive_letter: String, // e.g. "F:"
    pub volume_name: String,
    pub total_size: u64,
    pub free_space: u64,
    pub file_system: String,
    pub serial_number: String,
    pub insertion_time: u64,
}

/// Analysis results of files on a USB device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct USBFileAnalysis {
    pub total_files: usize,
    pub total_folders: usize,
    pub total_size: u64,
    pub file_types: HashMap<String, usize>,
    pub file_list: Vec<String>,
    pub suspicious_files: Vec<String>,
}

impl USBFileAnalysis {
    /// Creates an empty analysis result, used for alerts where no scan was performed.
    fn empty() -> Self {
        Self {
            total_files: 0,
            total_folders: 0,
            total_size: 0,
            file_types: HashMap::new(),
            file_list: Vec::new(),
            suspicious_files: Vec::new(),
        }
    }
}

// ===== USB PROTECTION MODULE =====

/// USB protection module that monitors and controls USB devices
pub struct USBProtection {
    known_devices: HashSet<String>, // Tracks known USB devices (drive letters like "F:")
    known_files: HashSet<String>,   // Track files we've already seen (full path strings)
    last_scan_time: u64,            // Last scan time for rate limiting (epoch seconds)
}

impl USBProtection {
    /// Create a new USB protection module
    pub fn new() -> Self {
        Self {
            known_devices: HashSet::new(),
            known_files: HashSet::new(),
            last_scan_time: 0,
        }
    }

    /// Main monitoring logic for USB devices
    async fn execute_monitoring(
        &mut self,
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        
        // 1. Use the new, reliable scan method to find *only* removable drives
        let current_devices = self.scan_usb_devices();

        // 2. Process new device insertions
        for device in &current_devices {
            if !self.known_devices.contains(&device.drive_letter) {
                info!("🎯 New USB device detected: {}", device.drive_letter);
                self.known_devices.insert(device.drive_letter.clone());

                // --- Policy Enforcement (Highest priority first) ---

                // Policy 1: BLOCK (Highest Priority)
                if policy_engine.is_policy_active(POLICY_USB_DEVICE_BLOCK) {
                    warn!("🚫 USB BLOCKED by policy: {}", device.drive_letter);
                    self.handle_blocked_usb(device, communicator, agent_id, token).await?;
                    continue; // Stop processing other policies for this device
                }
                
                // Policy 2: MONITOR CONNECTION (Send simple alert)
                if policy_engine.is_policy_active(POLICY_USB_DEVICE_MONITOR) {
                    info!("👀 USB CONNECTION MONITORED: {}", device.drive_letter);
                    self.send_usb_alert(device, &USBFileAnalysis::empty(), "MONITORED", communicator, agent_id, token).await?;
                }

                // Policy 3: SCAN FILES (Send detailed alert)
                if policy_engine.is_policy_active(POLICY_USB_SCAN_FILES) {
                    info!(" SCANNING FILES on USB: {}", device.drive_letter);
                    let file_analysis = self.analyze_usb_files(&device.drive_letter);
                    self.send_usb_alert(device, &file_analysis, "SCANNED", communicator, agent_id, token).await?;
                }
                
                // Policy 4 & 5: FILE CONTENT MONITORING (Block Executables, Detect Suspicious)
                if policy_engine.is_policy_active(POLICY_USB_BLOCK_EXECUTABLES) || 
                   policy_engine.is_policy_active(POLICY_USB_DETECT_SUSPICIOUS) {
                    self.monitor_file_operations(&device.drive_letter, policy_engine, communicator, agent_id, token).await?;
                }
            }
        }

        // 3. Process device removals
        let current_drives: HashSet<String> = current_devices.iter().map(|d| d.drive_letter.clone()).collect();
        self.known_devices.retain(|known_drive| {
            let is_still_connected = current_drives.contains(known_drive);
            if !is_still_connected {
                info!("📤 USB device removed: {}", known_drive);
            }
            is_still_connected // Keep if true, remove if false
        });
        
        self.last_scan_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(())
    }

    /// Handle a USB device that should be blocked
    async fn handle_blocked_usb(
        &self,
        device: &USBDeviceInfo,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        
        warn!("🛑 USB device {} has been blocked by DLP policy. Attempting eject.", device.drive_letter);
        
        // 1. Send the alert *before* ejecting
        self.send_usb_alert(device, &USBFileAnalysis::empty(), "BLOCKED", communicator, agent_id, token).await?;

        // 2. Format the drive path for the Windows API
        // We need a path like "\\.\E:"
        let volume_path_str = format!(r"\\.\{}", device.drive_letter);
        let mut volume_path_w: Vec<u16> = volume_path_str.encode_utf16().collect();
        volume_path_w.push(0); // Null terminator

        unsafe {
            // 3. Get a "handle" to the drive
            let handle = CreateFileW(
                volume_path_w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                error!("Failed to get handle for drive {}. Cannot eject.", device.drive_letter);
                return Ok(());
            }

            // 4. Send the "Eject" command to the drive
            let mut bytes_returned: u32 = 0;
            let result = DeviceIoControl(
                handle,
                IOCTL_STORAGE_EJECT_MEDIA,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            );

            if result == 0 {
                error!("Failed to send eject command to {}. The drive may be in use.", device.drive_letter);
            } else {
                info!("✅ Successfully ejected device {}", device.drive_letter);
            }

            // 5. Close the handle
            CloseHandle(handle);
        }
        
        Ok(())
    }

    /// Monitor file operations on a USB drive (single scan pass)
    async fn monitor_file_operations(
        &mut self,
        drive_letter: &str,
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let drive_path = format!("{}\\", drive_letter);
        
        let current_files = match Self::scan_files(&drive_path) {
            Ok(files) => files,
            Err(e) => {
                warn!("⚠️ Cannot scan files on drive {}: {}", drive_letter, e);
                return Ok(());
            }
        };

        let new_files: Vec<String> = current_files.iter()
            .filter(|file_path| !self.known_files.contains(*file_path))
            .cloned()
            .collect();

        if !new_files.is_empty() {
            info!("📄 Found {} new files on USB drive {}", new_files.len(), drive_letter);
            
            for file_path in &new_files {
                let path = Path::new(file_path);
                
                if policy_engine.is_policy_active(POLICY_USB_BLOCK_EXECUTABLES) {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        let ext_lower = ext.to_lowercase();
                        let executable_extensions = ["exe", "bat", "msi", "ps1", "cmd", "com", "scr", "vbs"];
                        
                        if executable_extensions.contains(&ext_lower.as_str()) {
                            warn!("🚫 Executable file BLOCKED by policy: {}", file_path);
                            
                            if let Err(e) = fs::remove_file(file_path) {
                                error!("❌ Failed to remove blocked file {}: {}", file_path, e);
                            } else {
                                info!("✅ Blocked executable file removed: {}", file_path);
                                Self::send_file_block_alert(communicator, agent_id, token, file_path, &ext_lower, POLICY_USB_BLOCK_EXECUTABLES).await?;
                            }
                            continue;
                        }
                    }
                }
                
                if policy_engine.is_policy_active(POLICY_USB_DETECT_SUSPICIOUS) {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if self.is_suspicious_file(&ext.to_lowercase(), path) {
                            warn!("⚠️ Suspicious file detected by policy: {}", file_path);
                            Self::send_suspicious_file_alert(communicator, agent_id, token, file_path).await?;
                        }
                    }
                }
            }
            
            self.known_files.extend(new_files);
        }
        Ok(())
    }

    // ===== WINDOWS API USB DETECTION =====

    /// Scan for USB devices on the system using the Windows API.
    pub fn scan_usb_devices(&self) -> Vec<USBDeviceInfo> {
        info!("🔍 Scanning for removable USB drives...");
        let mut devices = Vec::new();
        
        let drive_mask = unsafe { GetLogicalDrives() };

        for i in 0..26 {
            if (drive_mask >> i) & 1 == 1 {
                let drive_letter = (b'A' + i) as char;
                let drive_path_str = format!("{}:\\", drive_letter);

                if self.is_removable_drive(&drive_path_str) {
                    info!("✅ Found removable drive: {}", drive_path_str);
                    if let Some(device_info) = self.get_drive_info(&drive_path_str) {
                        devices.push(device_info);
                    }
                } else {
                    debug!("  Ignoring non-removable drive: {}", drive_path_str);
                }
            }
        }
        info!("📊 Scan complete. Found {} removable drives.", devices.len());
        devices
    }

    /// Check if a drive is a removable drive (like a USB stick).
    fn is_removable_drive(&self, drive_path: &str) -> bool {
        let mut path_w: Vec<u16> = drive_path.encode_utf16().collect();
        path_w.push(0); // Null-terminate the string

        let drive_type = unsafe { GetDriveTypeW(path_w.as_ptr()) };

        // Use the correctly imported constant
        drive_type == 2
    }

    // ===== UTILITY & FILE ANALYSIS METHODS =====

    /// Get information about a drive (Prototype)
    fn get_drive_info(&self, drive_path: &str) -> Option<USBDeviceInfo> {
        let drive_letter = drive_path[0..2].to_string();
        
        let (volume_name, total_size) = self.get_real_drive_info_prototype(drive_path);

        Some(USBDeviceInfo {
            drive_letter,
            volume_name,
            total_size,
            free_space: 0, // Placeholder
            file_system: "Unknown".to_string(), // Placeholder
            serial_number: "Unknown".to_string(), // Placeholder
            insertion_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        })
    }

    /// Prototype method to get drive info.
    fn get_real_drive_info_prototype(&self, drive_path: &str) -> (String, u64) {
        let mut volume_name = format!("Drive_{}", &drive_path[0..1]);
        let mut total_size = 0;
        
        if let Ok(output) = std::process::Command::new("cmd")
            .args(&["/C", &format!("vol {}", drive_path)])
            .output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("Volume in drive") && line.contains("is") {
                    if let Some(name_start) = line.find("is ") {
                        let name = line[name_start + 3..].trim();
                        if !name.is_empty() && name != "has no label" {
                            volume_name = name.to_string();
                        }
                    }
                }
            }
        }
        
        if let Ok(metadata) = fs::metadata(drive_path) {
            total_size = metadata.len(); 
        }
        
        (volume_name, total_size)
    }

    /// Scan files in a directory (top-level only)
    fn scan_files(drive_path: &str) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
        let mut files = HashSet::new();
        if let Ok(entries) = fs::read_dir(drive_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(path_str) = path.to_str() {
                        files.insert(path_str.to_string());
                    }
                }
            }
        }
        Ok(files)
    }

    /// Analyze files on a USB drive (recursive)
    pub fn analyze_usb_files(&self, drive_letter: &str) -> USBFileAnalysis {
        let mut analysis = USBFileAnalysis::empty();
        let drive_path = format!("{}\\", drive_letter);
        info!("   📁 Scanning all files and folders on {}...", drive_letter);
        self.analyze_directory(Path::new(&drive_path), &mut analysis);
        info!("   📊 Scan complete: Found {} files, {} folders", analysis.total_files, analysis.total_folders);
        analysis
    }

    /// Recursively analyze directory
    fn analyze_directory(&self, dir_path: &Path, analysis: &mut USBFileAnalysis) {
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    analysis.total_folders += 1;
                    self.analyze_directory(&path, analysis);
                } else if path.is_file() {
                    self.analyze_file(&path, analysis);
                }
            }
        }
    }

    /// Analyze a single file
    fn analyze_file(&self, file_path: &Path, analysis: &mut USBFileAnalysis) {
        analysis.total_files += 1;
        
        let extension = file_path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("no_extension")
            .to_lowercase();
        
        *analysis.file_types.entry(extension.clone()).or_insert(0) += 1;
        
        if let Ok(metadata) = fs::metadata(file_path) {
            analysis.total_size += metadata.len();
        }
        
        if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
            analysis.file_list.push(file_name.to_string());
        }
        
        if self.is_suspicious_file(&extension, file_path) {
            if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
                analysis.suspicious_files.push(file_name.to_string());
            }
        }
    }

    /// Check if a file is suspicious by extension or name
    fn is_suspicious_file(&self, extension: &str, file_path: &Path) -> bool {
        let suspicious_extensions = [
            "exe", "bat", "cmd", "ps1", "vbs", "js", "jar", "scr", "pif", "com", "msi"
        ];
        let suspicious_keywords = [
            "keygen", "crack", "serial", "patch", "loader", "activator", "torrent", "hack", "exploit"
        ];
        
        if suspicious_extensions.contains(&extension) {
            return true;
        }
        
        if let Some(filename) = file_path.file_name().and_then(|name| name.to_str()) {
            let filename_lower = filename.to_lowercase();
            for keyword in &suspicious_keywords {
                if filename_lower.contains(keyword) {
                    return true;
                }
            }
        }
        false
    }

    // --- ALERT SENDING METHODS ---

    /// Send a generic USB alert to the backend
    async fn send_usb_alert(
        &self,
        device: &USBDeviceInfo,
        file_analysis: &USBFileAnalysis,
        action: &str,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let alert_data = serde_json::json!({
            "agentId": agent_id,
            "alertType": if action == "BLOCKED" { "USB_BLOCKED" } else { "USB_INSERTION" },
            "description": format!("USB device detected: {}. Action: {}.", device.drive_letter, action),
            "deviceInfo": format!("Drive: {}, Volume: {}, Size: {}GB", 
                                 device.drive_letter, device.volume_name, 
                                 device.total_size / 1_000_000_000),
            "fileDetails": format!("Files: {}, Folders: {}, Total Size: {}MB, Suspicious: {}", 
                                  file_analysis.total_files, file_analysis.total_folders,
                                  file_analysis.total_size / 1_000_000, file_analysis.suspicious_files.len()),
            "severity": if action == "BLOCKED" { "HIGH" } else { "MEDIUM" },
            "actionTaken": action
        });
    
        info!("📤 Sending USB alert to backend...");
        communicator.send_alert(&alert_data, token).await
    }

    /// Send a specific "file blocked" alert
    async fn send_file_block_alert(
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str,
        file_path: &str,
        file_extension: &str,
        policy_code: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let alert_data = serde_json::json!({
            "agentId": agent_id,
            "alertType": "FILE_BLOCKED",
            "description": format!("Executable file blocked by policy: {}", file_path),
            "deviceInfo": "USB Device",
            "fileDetails": format!("File: {}, Extension: {}, Policy: {}", file_path, file_extension, policy_code),
            "severity": "HIGH",
            "actionTaken": "BLOCKED"
        });
        communicator.send_alert(&alert_data, token).await
    }

    /// Send a specific "suspicious file" alert
    async fn send_suspicious_file_alert(
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str,
        file_path: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let alert_data = serde_json::json!({
            "agentId": agent_id,
            "alertType": "SUSPICIOUS_FILE_DETECTED",
            "description": format!("Suspicious file detected on USB: {}", file_path),
            "deviceInfo": "USB Device", 
            "fileDetails": format!("File: {}", file_path),
            "severity": "MEDIUM",
            "actionTaken": "DETECTED"
        });
        communicator.send_alert(&alert_data, token).await
    }
}

// ===== PROTECTION MODULE IMPLEMENTATION =====

#[async_trait::async_trait]
impl ProtectionModule for USBProtection {
    /// Execute USB protection based on active policies
    async fn execute(
        &mut self,
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Only run if any USB protection policy is active
        if policy_engine.is_usb_protection_enabled() {
            self.execute_monitoring(policy_engine, communicator, agent_id, token).await?;
        }
        Ok(())
    }
   
    /// Get module name
    fn get_name(&self) -> &str {
        "USB"
    }
}