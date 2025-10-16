// // capabilities.rs
// // Defines what policies the agent can enforce and reports them to backend

// use serde::{Deserialize, Serialize};

// /// Represents a policy capability that this agent can enforce
// /// This is sent to the backend so admin knows what policies are available
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct PolicyCapability {
//     pub code: String,        // Unique policy code (matches policy_constants)
//     pub name: String,        // Human-readable name
//     pub description: String, // Detailed description
//     pub category: String,    // Category: USB, FILE, NETWORK
//     pub action: String,      // Action: BLOCK, MONITOR, ALLOW
//     pub target: String,      // What the policy targets
//     pub severity: String,    // Severity: HIGH, MEDIUM, LOW
// }

// impl PolicyCapability {
//     /// Returns all capabilities this agent supports
//     pub fn all_capabilities() -> Vec<Self> {
//         let mut capabilities = Vec::new();
        
//         // Add all capability categories
//         capabilities.extend(Self::usb_capabilities());
//         capabilities.extend(Self::file_capabilities());
//         capabilities.extend(Self::network_capabilities());
        
//         capabilities
//     }
    
//     /// USB protection capabilities that this agent can enforce
//     pub fn usb_capabilities() -> Vec<Self> {
//         use crate::policy_constants::*;
        
//         vec![
//             PolicyCapability {
//                 code: POLICY_USB_DEVICE_BLOCK.to_string(),
//                 name: "Block USB Devices".to_string(),
//                 description: "Completely block all USB storage devices from being accessed".to_string(),
//                 category: "USB".to_string(),
//                 action: "BLOCK".to_string(),
//                 target: "ALL_USB_STORAGE".to_string(),
//                 severity: "HIGH".to_string(),
//             },
//             PolicyCapability {
//                 code: POLICY_USB_DEVICE_MONITOR.to_string(),
//                 name: "Monitor USB Devices".to_string(),
//                 description: "Monitor USB device insertion/removal and file operations".to_string(),
//                 category: "USB".to_string(),
//                 action: "MONITOR".to_string(),
//                 target: "ALL_USB_DEVICES".to_string(),
//                 severity: "MEDIUM".to_string(),
//             },
//             PolicyCapability {
//                 code: POLICY_USB_BLOCK_EXECUTABLES.to_string(),
//                 name: "Block Executable Files".to_string(),
//                 description: "Block executable files: .exe, .bat, .msi, .ps1 on USB devices".to_string(),
//                 category: "USB".to_string(),
//                 action: "BLOCK".to_string(),
//                 target: "exe,bat,msi,ps1".to_string(),
//                 severity: "HIGH".to_string(),
//             },
//             PolicyCapability {
//                 code: POLICY_USB_DETECT_SUSPICIOUS.to_string(),
//                 name: "Detect Suspicious Files".to_string(),
//                 description: "Detect and alert on suspicious files (keygens, cracks, exploits)".to_string(),
//                 category: "USB".to_string(),
//                 action: "MONITOR".to_string(),
//                 target: "suspicious_keywords".to_string(),
//                 severity: "MEDIUM".to_string(),
//             }
//         ]
//     }
    
//     /// File protection capabilities
//     pub fn file_capabilities() -> Vec<Self> {
//         use crate::policy_constants::*;
        
//         vec![
//             PolicyCapability {
//                 code: POLICY_FILE_MONITOR_ACCESS.to_string(),
//                 name: "Monitor File Access".to_string(),
//                 description: "Monitor file access and operations on the system".to_string(),
//                 category: "FILE".to_string(),
//                 action: "MONITOR".to_string(),
//                 target: "ALL_FILES".to_string(),
//                 severity: "LOW".to_string(),
//             }
//         ]
//     }
    
//     /// Network protection capabilities
//     pub fn network_capabilities() -> Vec<Self> {
//         use crate::policy_constants::*;
        
//         vec![
//             PolicyCapability {
//                 code: POLICY_NETWORK_MONITOR.to_string(),
//                 name: "Monitor Network Activity".to_string(),
//                 description: "Monitor network file transfers".to_string(),
//                 category: "NETWORK".to_string(),
//                 action: "MONITOR".to_string(),
//                 target: "NETWORK_TRANSFERS".to_string(),
//                 severity: "LOW".to_string(),
//             }
//         ]
//     }
// }

use serde::{Deserialize, Serialize};
use crate::policy_constants::*; // Make sure you have the constants defined

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCapability {
    pub code: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub action: String,
    pub target: String,
    pub severity: String,
}

impl PolicyCapability {
    /// Returns all capabilities this agent supports by combining them from each category.
    pub fn all_capabilities() -> Vec<Self> {
        [
            Self::usb_capabilities(),
            // You can add Self::network_capabilities(), Self::file_capabilities() here later
        ].concat()
    }

    /// Defines the specific, granular capabilities related to USB protection.
    /// Each of these now corresponds to a function/check in your usb_protection.rs file.
    pub fn usb_capabilities() -> Vec<Self> {
        vec![
            PolicyCapability {
                code: POLICY_USB_DEVICE_BLOCK.to_string(),
                name: "Block All USB Drives".to_string(),
                description: "Completely block all USB storage devices from being used.".to_string(),
                category: "USB".to_string(),
                action: "BLOCK".to_string(),
                target: "ALL_USB_STORAGE".to_string(),
                severity: "HIGH".to_string(),
            },
            PolicyCapability {
                code: POLICY_USB_DEVICE_MONITOR.to_string(),
                name: "Monitor USB Connections".to_string(),
                description: "Create an alert whenever a USB device is connected or disconnected.".to_string(),
                category: "USB".to_string(),
                action: "MONITOR".to_string(),
                target: "USB_CONNECTIONS".to_string(),
                severity: "LOW".to_string(),
            },
            PolicyCapability {
                code: POLICY_USB_SCAN_FILES.to_string(), // New constant needed
                name: "Scan Files on USB".to_string(),
                description: "Analyze and report all files and folders when a USB is connected.".to_string(),
                category: "USB".to_string(),
                action: "MONITOR".to_string(),
                target: "FILE_SYSTEM".to_string(),
                severity: "MEDIUM".to_string(),
            },
            PolicyCapability {
                code: POLICY_USB_BLOCK_EXECUTABLES.to_string(),
                name: "Block Executable Files on USB".to_string(),
                description: "Prevent running or copying of executable files (.exe, .bat, etc.) from USB drives.".to_string(),
                category: "USB".to_string(),
                action: "BLOCK".to_string(),
                target: "EXECUTABLES".to_string(),
                severity: "HIGH".to_string(),
            },
            PolicyCapability {
                code: POLICY_USB_DETECT_SUSPICIOUS.to_string(),
                name: "Detect Suspicious Files on USB".to_string(),
                description: "Alert when files with suspicious names (e.g., 'crack', 'keygen') are found on a USB drive.".to_string(),
                category: "USB".to_string(),
                action: "MONITOR".to_string(),
                target: "SUSPICIOUS_KEYWORDS".to_string(),
                severity: "HIGH".to_string(),
            },
        ]
    }
}