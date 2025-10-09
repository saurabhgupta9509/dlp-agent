// policy_engine.rs
// Manages policies and provides methods to check which policies are active

use serde::{Deserialize, Serialize};
use crate::policy_constants::*;

/// Represents a policy that can be assigned to an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub policy_code: String,  // Unique identifier (matches policy_constants)
    pub name: String,         // Human-readable name
    pub description: String,  // What the policy does
    pub category: String,     // USB, FILE, NETWORK
    pub policy_type: String,  // Type of policy
    pub action: String,       // BLOCK, MONITOR, ALLOW
    pub target: String,       // What the policy targets
    pub severity: String,     // HIGH, MEDIUM, LOW
    pub is_active: bool,      // Whether this policy is currently active
}

/// Main engine that manages policies and provides checking methods
pub struct PolicyEngine {
    policies: Vec<Policy>,  // All policies assigned to this agent
}

impl PolicyEngine {
    /// Create a new PolicyEngine with no policies
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }
    
    /// Update the policies from backend
    pub fn update_policies(&mut self, policies: Vec<Policy>) {
        self.policies = policies;
        log::debug!("🔄 Updated PolicyEngine with {} policies", self.policies.len());
    }
    
    /// Get number of policies
    pub fn get_policy_count(&self) -> usize {
        self.policies.len()
    }
    
    // ===== SPECIFIC POLICY CHECKS =====
    // These methods check if specific policies are active
    
    /// Check if USB device blocking is enabled
    pub fn should_block_usb_devices(&self) -> bool {
        self.policies.iter().any(|p| p.policy_code == POLICY_USB_DEVICE_BLOCK && p.is_active)
    }
    
    /// Check if USB device monitoring is enabled
    pub fn should_monitor_usb_devices(&self) -> bool {
        self.policies.iter().any(|p| p.policy_code == POLICY_USB_DEVICE_MONITOR && p.is_active)
    }
    
    /// Check if executable file blocking on USB is enabled
    pub fn should_block_executable_files(&self) -> bool {
        self.policies.iter().any(|p| p.policy_code == POLICY_USB_BLOCK_EXECUTABLES && p.is_active)
    }
    
    /// Check if suspicious file detection is enabled
    pub fn should_detect_suspicious_files(&self) -> bool {
        self.policies.iter().any(|p| p.policy_code == POLICY_USB_DETECT_SUSPICIOUS && p.is_active)
    }
    
    // ===== CATEGORY CHECKS =====
    // These methods check if any policy in a category is active
    
    /// Check if any USB protection is enabled
    pub fn is_usb_protection_enabled(&self) -> bool {
        self.policies.iter().any(|p| p.category == "USB" && p.is_active)
    }
    
    /// Check if any file protection is enabled
    pub fn is_file_protection_enabled(&self) -> bool {
        self.policies.iter().any(|p| p.category == "FILE" && p.is_active)
    }
    
    /// Check if any network protection is enabled
    pub fn is_network_protection_enabled(&self) -> bool {
        self.policies.iter().any(|p| p.category == "NETWORK" && p.is_active)
    }
    
    /// Get all active policies (for debugging/monitoring)
    pub fn get_active_policies(&self) -> Vec<&Policy> {
        self.policies.iter().filter(|p| p.is_active).collect()
    }
    
    /// Check if a specific policy code is active
    pub fn is_policy_active(&self, policy_code: &str) -> bool {
        self.policies.iter().any(|p| p.policy_code == policy_code && p.is_active)
    }
}