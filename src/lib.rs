pub mod communication;
pub mod policy_engine;
pub mod agent_core;
pub mod protection_modules;
pub mod gui;  // Add this line
pub mod capabilities;
pub mod policy_constants;
// Re-export the main types
pub use agent_core::AgentCore;
pub use gui::AgentGUI;  // Add this line
pub use communication::ServerCommunicator;
pub use policy_engine::{PolicyEngine, Policy};