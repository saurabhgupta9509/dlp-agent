// policy_constants.rs
// Defines all policy codes as constants to ensure consistency between Rust and Java

// USB Protection Policies
pub const POLICY_USB_DEVICE_BLOCK: &str = "USB_DEVICE_BLOCK";
pub const POLICY_USB_DEVICE_MONITOR: &str = "USB_DEVICE_MONITOR";
pub const POLICY_USB_BLOCK_EXECUTABLES: &str = "USB_BLOCK_EXECUTABLES";
pub const POLICY_USB_DETECT_SUSPICIOUS: &str = "USB_DETECT_SUSPICIOUS";
pub const POLICY_USB_SCAN_FILES: &str = "USB_SCAN_FILES";
// File Protection Policies  
pub const POLICY_FILE_MONITOR_ACCESS: &str = "FILE_MONITOR_ACCESS";

// Network Protection Policies
pub const POLICY_NETWORK_MONITOR: &str = "NETWORK_MONITOR";