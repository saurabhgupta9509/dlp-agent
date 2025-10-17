// agent_core.rs
// Main agent core that coordinates all components and runs the protection loop

use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;
use crate::protection_modules::network_protection::NetworkProtection;
use crate::protection_modules::ProtectionModule;
use crate::capabilities::PolicyCapability;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time;
use log;
use crate::config::BASE_URL;

/// Configuration for the agent
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub server_url: String,           // Backend server URL
    pub hostname: String,             // Agent hostname
    pub mac_address: String,          // Agent MAC address
    pub poll_interval_sec: u64,       // How often to poll for updates
}

/// Main agent core that coordinates all components
pub struct AgentCore {
    
    pub agent_id: u64,                           // Agent ID from backend
    pub token: String,                           // Authentication token
    pub config: AgentConfig,                     // Agent configuration
    pub policy_engine: PolicyEngine,             // Policy management
    pub communicator: ServerCommunicator,        // Server communication
    pub protection_modules: HashMap<String, Box<dyn ProtectionModule>>, // Active protection modules
}

impl AgentCore {
    /// Create a new AgentCore with default configuration
    pub fn new() -> Self {
        let config = AgentConfig {
            server_url: BASE_URL.to_string(),
            hostname: whoami::hostname(),
            mac_address: get_mac_address(),
            poll_interval_sec: 01,
        };

        Self {
            agent_id: 0,
            token: String::new(),
            config,
            policy_engine: PolicyEngine::new(),
            communicator: ServerCommunicator::new(),
            protection_modules: HashMap::new(),
        }
    }

    /// Initialize the agent - authenticate and report capabilities
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("🚀 Initializing agent...");
        

        if self.token.is_empty() {
            return Err("AgentCore started without a valid token.".into());
        }
        // Step 1: Authenticate with server
        // self.authenticate_with_server().await?;
        
        // Step 2: Report capabilities to backend
        let capabilities = PolicyCapability::all_capabilities();
        self.communicator.report_capabilities(self.agent_id, &self.token, &capabilities).await?;
        
        // Step 3: Initialize protection modules
        self.initialize_protection_modules();
        
        // Step 4: Fetch initial active policies
        self.fetch_policies().await?;
        
        log::info!("✅ Agent initialized with {} capabilities", capabilities.len());
        Ok(())
    }

    /// Authenticate with the backend server
    pub async fn authenticate_with_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("🔐 Authenticating with DLP protection server...");
        
        // Step 1: Register agent to get credentials
        self.communicator.agent_register(&self.config.hostname, &self.config.mac_address).await?;
        
        // Step 2: Login with those credentials to get session token
        self.communicator.agent_login().await?;
        
        // Store the agent_id and token from the communicator's credentials
        if let Some(creds) = &self.communicator.credentials {
            self.agent_id = creds.agent_id;
            if let Some(token) = &creds.token {
                self.token = token.clone();
                // self.token = format!("Bearer {}", token);
                log::info!("✅ Token stored successfully.");
            }
        }
        
        log::info!("✅ Authentication successful. Agent ID: {}", self.agent_id);
        Ok(())
    }

    /// Main agent loop - runs continuously
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("🔄 Starting agent main loop...");
        
        // Set up polling interval
        let mut interval = time::interval(Duration::from_secs(self.config.poll_interval_sec));
        
        // Main loop
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Execute one polling cycle
                    if let Err(e) = self.poll_cycle().await {
                        log::error!("❌ Poll cycle error: {}", e);
                    }
                }
            }
        }
    }

    /// Single polling cycle - called repeatedly by main loop
    async fn poll_cycle(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        log::debug!("🔄 Polling cycle started");
        
        // 1. Send heartbeat to show we're alive
        if let Err(e) = self.send_heartbeat().await {
            log::warn!("⚠️ Heartbeat failed: {}", e);
        }
        
        // 2. Fetch updated policies from backend
        if let Err(e) = self.fetch_policies().await {
            log::warn!("⚠️ Policy fetch failed: {}", e);
        }
        
        // 3. Execute protections based on active policies
        if let Err(e) = self.execute_protections().await {
            log::warn!("⚠️ Protection execution failed: {}", e);
        }
        
        log::debug!("✅ Polling cycle completed");
        Ok(())
    }

    /// Fetch active policies from backend and update policy engine
    async fn fetch_policies(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let policies = self.communicator.get_active_policies(self.agent_id, &self.token).await?;
        self.policy_engine.update_policies(policies);
        
        let active_count = self.policy_engine.get_active_policies().len();
        log::info!("📋 Updated policies: {} active, {} total", 
                  active_count, self.policy_engine.get_policy_count());
        
        Ok(())
    }

    /// Execute all protection modules based on active policies
   // agent_core.rs - Update the execute_protections method

async fn execute_protections(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    // Create a list of modules that should run BEFORE the mutable borrow
    let modules_to_run: Vec<String> = self.protection_modules
        .keys()
        .filter(|module_name| self.should_run_protection_module(module_name))
        .cloned()
        .collect();
    
    // Now iterate over the modules that should run
    for module_name in modules_to_run {
        if let Some(module) = self.protection_modules.get_mut(&module_name) {
            log::debug!("🛡️ Executing protection module: {}", module_name);
            
            if let Err(e) = module.execute(&self.policy_engine, &self.communicator, self.agent_id, &self.token).await {
                log::error!("❌ Protection module {} failed: {}", module_name, e);
            }
        }
    }
    Ok(())
}

    /// Check if a protection module should run based on active policies
    fn should_run_protection_module(&self, module_name: &str) -> bool {
        match module_name {
            "USB" => self.policy_engine.is_usb_protection_enabled(),
            "FILE" => self.policy_engine.is_file_protection_enabled(),
            "NETWORK" => self.policy_engine.is_network_protection_enabled(),
            _ => false,
        }
    }

    /// Send heartbeat to backend
    async fn send_heartbeat(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.communicator.send_heartbeat(self.agent_id, &self.token).await
    }

    /// Initialize all protection modules
    fn initialize_protection_modules(&mut self) {
        use crate::protection_modules::usb_protection::USBProtection;
        
        // Initialize USB protection
        self.protection_modules.insert(
            "USB".to_string(),
            Box::new(USBProtection::new())
        );
        
        // TODO: Initialize other protection modules
        // self.protection_modules.insert("FILE".to_string(), Box::new(FileProtection::new()));
        // self.protection_modules.insert("NETWORK".to_string(), Box::new(NetworkProtection::new()));
        let network_module = NetworkProtection::new()
            .expect("FATAL: Failed to initialize Network Protection. Are you running as Administrator?");
            
        self.protection_modules.insert(
            "NETWORK".to_string(),
            Box::new(network_module)
        );
        
        log::info!("✅ Initialized {} protection modules", self.protection_modules.len());
    }

    /// Get active policies for debugging
    pub fn get_active_policies_info(&self) -> String {
        let active_policies = self.policy_engine.get_active_policies();
        if active_policies.is_empty() {
            return "No active policies".to_string();
        }
        
        let mut info = String::from("Active policies:\n");
        for policy in active_policies {
            info.push_str(&format!("  • {} ({})\n", policy.name, policy.code));
        }
        info
    }
}

/// Get MAC address (simplified implementation)
fn get_mac_address() -> String {
    // In production, use proper system calls to get real MAC address
    // This is a simplified version for demonstration
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        rng.gen_range(0..255),
        rng.gen_range(0..255), 
        rng.gen_range(0..255),
        rng.gen_range(0..255),
        rng.gen_range(0..255),
        rng.gen_range(0..255)
    )
}