// protection_modules/mod.rs
// Defines the interface for all protection modules

pub mod usb_protection;

use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;

/// Trait that all protection modules must implement
#[async_trait::async_trait]
pub trait ProtectionModule: Send + Sync {
    /// Execute the protection module's main logic
    async fn execute(
        &mut self, 
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Get the name of this protection module
    fn get_name(&self) -> &str;
}