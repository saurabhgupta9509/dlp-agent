use serde::{Deserialize, Serialize};
use crate::policy_constants::*;
use log::{warn, debug};
use serde_json;

/// Represents a policy received from the backend.
/// This struct MUST match the Java PolicyCapabilityDTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub code: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub action: String,
    pub target: String,
    pub severity: String,
    pub is_active: bool,
    
    // This field holds custom data, like the JSON string for the DNS blocklist.
    // #[serde(default)] ensures that if the field is null or missing,
    // the code won't crash and will just use an empty string.
    #[serde(default)]
    pub policy_data: String, 
}

/// Main engine that manages policies and provides checking methods.
pub struct PolicyEngine {
    policies: Vec<Policy>,
}

impl PolicyEngine {
    /// Create a new PolicyEngine.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Updates the engine with a new set of policies from the backend.
    pub fn update_policies(&mut self, policies: Vec<Policy>) {
        self.policies = policies;
        debug!("🔄 Updated PolicyEngine with {} policies", self.policies.len());
    }

    /// Gets and parses the JSON string from a policy's `policy_data` field.
    /// Returns a default `T` if the policy is not active or parsing fails.
    pub fn get_policy_json_data<T: for<'de> serde::Deserialize<'de> + Default>(
        &self,
        policy_code: &str
    ) -> T {
        if let Some(policy) = self.policies.iter().find(|p| p.code == policy_code && p.is_active) {
            // First, check if the data string is empty. If it is, return a default
            // value (e.g., an empty list) without trying to parse it.
            if policy.policy_data.is_empty() {
                return T::default();
            }

            // Only try to parse if the string is NOT empty.
            serde_json::from_str(&policy.policy_data)
                .unwrap_or_else(|e| {
                    warn!("Failed to parse policy data for {}: {}. Data was: '{}'", policy_code, e, policy.policy_data);
                    T::default() // Return default if parsing fails.
                })
        } else {
            // If policy isn't active, return default.
            T::default()
        }
    }

    /// Checks if a specific policy code is active.
    pub fn is_policy_active(&self, policy_code: &str) -> bool {
        self.policies.iter().any(|p| p.code == policy_code && p.is_active)
    }
    
    // ===== CATEGORY CHECKS (For the AgentCore) =====

    /// Checks if any USB protection policy is active.
    pub fn is_usb_protection_enabled(&self) -> bool {
        self.policies.iter().any(|p| p.category == "USB" && p.is_active)
    }
    
    /// Checks if any Network protection policy is active.
    pub fn is_network_protection_enabled(&self) -> bool {
        self.is_policy_active(POLICY_NETWORK_DNS_BLOCK)
    }

    /// Checks if any File protection policy is active.
    pub fn is_file_protection_enabled(&self) -> bool {
        self.policies.iter().any(|p| p.category == "FILE" && p.is_active)
    }
    
    // ===== DEBUGGING HELPERS =====
    
    /// Returns a list of all currently active policies.
    pub fn get_active_policies(&self) -> Vec<&Policy> {
        self.policies.iter().filter(|p| p.is_active).collect()
    }
    
    /// Returns the total number of policies (active and inactive).
    pub fn get_policy_count(&self) -> usize {
        self.policies.len()
    }
}