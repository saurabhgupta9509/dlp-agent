// gui.rs
// Command-line interface for the agent (optional - can be used for testing)

use dialoguer::{console::Style, Input, Select, Password};
use std::process;
use crate::communication::ServerCommunicator;

/// GUI for agent interaction and testing
pub struct AgentGUI {
    pub agent_id: u64,
    pub token: String,
    pub username: String,
    pub password: String,
    pub server_url: String,
    pub is_authenticated: bool,
    pub communicator: Option<ServerCommunicator>,
}

impl AgentGUI {
    /// Create new GUI
    pub fn new() -> Self {
        Self {
            agent_id: 0,
            token: String::new(),
            username: String::new(),
            password: String::new(),
            server_url: "http://192.168.128:8080".to_string(),
            is_authenticated: false,
            communicator: None,
        }
    }

    /// Main GUI loop
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting DLP Protection Agent...");
        
        loop {
            if !self.is_authenticated {
                self.show_main_menu().await?;
            } else {
                self.show_dashboard().await?;
            }
        }
    }

    /// Show main menu (authentication)
    async fn show_main_menu(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n{}", Style::new().bold().apply_to("🛡️ DLP Agent"));
        println!("{}", "=".repeat(25));

        let choices = &[
            "1. Register New Agent",
            "2. Login Existing Agent", 
            "3. Exit"
        ];

        let selection = Select::new()
            .with_prompt("Choose an option:")
            .items(choices)
            .default(0)
            .interact()?;

        match selection {
            0 => self.show_registration_screen().await?,
            1 => self.show_login_screen().await?,
            2 => {
                println!("👋 Goodbye!");
                std::process::exit(0);
            }
            _ => {}
        }

        Ok(())
    }

    /// Show registration screen
    async fn show_registration_screen(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n{}", Style::new().bold().apply_to("📝 Agent Registration"));
        println!("{}", "=".repeat(30));
    
        let hostname: String = Input::new()
            .with_prompt("Enter Hostname")
            .default(whoami::hostname())
            .interact_text()?;
    
        let mac_address: String = Input::new()
            .with_prompt("Enter MAC Address")
            .default("00:11:22:33:44:55".to_string())
            .interact_text()?;
    
        println!("\n🖥️  Hostname: {}", hostname);
        println!("📡 MAC Address: {}", mac_address);
        println!("⏳ Registering agent...");
    
        let mut communicator = ServerCommunicator::new();
        
        match communicator.agent_register(&hostname, &mac_address).await {
            Ok(_) => {
                println!("✅ Agent registered successfully!");
                
                println!("🔐 Attempting auto-login...");
                
                match communicator.agent_login().await {
                    Ok(_) => {
                        if let Some(creds) = communicator.get_credentials() {
                            self.agent_id = creds.agent_id;
                            self.username = creds.username.clone();
                            self.password = creds.password.clone();
                            self.is_authenticated = true;
                            self.communicator = Some(communicator);
                            
                            println!("✅ Agent authenticated successfully!");
                            println!("🎯 Agent ID: {}", self.agent_id);
                            println!("👤 Username: {}", self.username);
                            println!("🔐 Password: {}", self.password);
                        }
                    }
                    Err(e) => {
                        println!("❌ Auto-login failed: {}", e);
                        println!("💡 Please use 'Login Existing Agent' with the credentials above");
                    }
                }
            }
            Err(e) => {
                println!("❌ Registration failed: {}", e);
                if e.to_string().contains("already registered") {
                    println!("💡 This agent is already registered. Please use Login instead.");
                }
            }
        }
    
        Ok(())
    }

    /// Show login screen
    async fn show_login_screen(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n{}", Style::new().bold().apply_to("🔐 Agent Login"));
        println!("{}", "=".repeat(25));
    
        let username: String = Input::new()
            .with_prompt("Username")
            .interact_text()?;
    
        let password = Password::new()
            .with_prompt("Password")
            .interact()?;
    
        println!("⏳ Authenticating...");
    
        let mut communicator = ServerCommunicator::new();
        
        communicator.set_credentials(username.clone(), password.clone());
        
        match communicator.agent_login().await {
            Ok(_) => {
                if let Some(creds) = communicator.get_credentials() {
                    self.agent_id = creds.agent_id;
                    self.username = creds.username.clone();
                    self.password = creds.password.clone();
                    self.is_authenticated = true;
                    self.communicator = Some(communicator);
                    println!("✅ Login successful!");
                    println!("🎯 Agent ID: {}", self.agent_id);
                }
            }
            Err(e) => {
                println!("❌ Login failed: {}", e);
                println!("💡 Troubleshooting:");
                println!("   1. Check if username/password is correct");
                println!("   2. Verify backend is running on localhost:8080");
                println!("   3. Check backend logs for errors");
            }
        }
    
        Ok(())
    }

    /// Show dashboard after authentication
    async fn show_dashboard(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n{}", Style::new().bold().apply_to("🛡️ DLP Agent Dashboard"));
        println!("{}", "=".repeat(35));

        let choices = &[
            "1. View Profile & Status",
            "2. Refresh Policies", 
            "3. Test USB Protection",
            "4. View Active Policies",
            "5. Send Test Alert",
            "6. Logout",
            "7. Exit"
        ];

        let selection = Select::new()
            .with_prompt("Choose an option:")
            .items(choices)
            .default(0)
            .interact()?;

        match selection {
            0 => self.view_profile().await?,
            1 => self.refresh_policies().await?,
            2 => self.test_usb_protection().await?,
            3 => self.view_active_policies().await?,
            4 => self.send_test_alert().await?,
            5 => {
                self.logout();
                println!("👋 Logged out successfully!");
            }
            6 => {
                println!("👋 Goodbye!");
                process::exit(0);
            }
            _ => {}
        }

        Ok(())
    }

    /// View agent profile
    async fn view_profile(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n{}", Style::new().bold().apply_to("📊 Agent Profile"));
        println!("{}", "-".repeat(25));
        println!("🆔 Agent ID: {}", self.agent_id);
        println!("🖥️  Hostname: {}", whoami::hostname());
        println!("🌐 Server: {}", self.server_url);
        println!("🔐 Status: {}", Style::new().green().apply_to("Authenticated"));
        
        Ok(())
    }

    /// Refresh policies from backend
    async fn refresh_policies(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🔄 Refreshing policies...");
        
        if let Some(comm) = &self.communicator {
            match comm.get_agent_policies().await {
                Ok(policies) => {
                    println!("✅ Retrieved {} policies from server", policies.len());
                    for policy in policies {
                        let status = if policy.is_active { 
                            Style::new().green().apply_to("ACTIVE") 
                        } else { 
                            Style::new().yellow().apply_to("INACTIVE") 
                        };
                        println!("   • {} - {} [{}]", policy.name, policy.action, status);
                    }
                }
                Err(e) => {
                    println!("❌ Failed to refresh policies: {}", e);
                }
            }
        }
        
        Ok(())
    }

    /// Test USB protection with actual detection
async fn test_usb_protection(&self) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", Style::new().bold().apply_to("🧪 USB Protection Test"));
    
    use crate::protection_modules::usb_protection::USBProtection;
    
    let usb_protection = USBProtection::new();
    
    // First, run debug detection
    // usb_protection.debug_drive_detection();
    
    println!("\nScanning for USB devices...");
    let devices = usb_protection.scan_usb_devices();
    
    if devices.is_empty() {
        println!("❌ No USB removable devices found");
        println!("💡 Make sure:");
        println!("   - USB drive is properly inserted");
        println!("   - Drive appears in Windows as removable media");
        println!("   - Try different USB port");
    } else {
        println!("✅ Found {} USB device(s):", devices.len());
        
        // // for (index, device) in devices.iter().enumerate() {
        //     println!("\n  {}. Drive: {}", index + 1, device.drive_letter);
        //     println!("     Volume: {}", device.volume_name);
        //     println!("     Size: {} bytes", device.total_size / 1_000_000_000);
        //     println!("     File System: {}", device.file_system);
        for device in &devices {
            println!("\n  Drive: {}", device.drive_letter);
            println!("  Volume: {}", device.volume_name);
            println!("  Size: {} GB", device.total_size / 1_000_000_000);
            println!("     File System: {}", device.file_system);

            // Analyze files on the USB
            println!("     Analyzing files...");
            let file_analysis = usb_protection.analyze_usb_files(&device.drive_letter);
            
            println!("     Files: {}", file_analysis.total_files);
            println!("     Folders: {}", file_analysis.total_folders);
            println!("     Total Size: {} bytes", file_analysis.total_size);
            
            if !file_analysis.file_types.is_empty() {
                println!("     File Types:");
                for (file_type, count) in &file_analysis.file_types {
                    println!("       - {}: {}", file_type, count);
                }
            }
            if device.drive_letter == "E:" {
                println!("     🎯 This is likely your USB drive (E:)");
            }
            
            if !file_analysis.suspicious_files.is_empty() {
                println!("     ⚠️  Suspicious Files:");
                for file in &file_analysis.suspicious_files {
                    println!("       - {}", file);
                }
            }
        }
        
        println!("\n🔍 Testing policy enforcement...");
        
        // Test what would happen with different policies
        println!("   With USB_DEVICE_BLOCK: 🚫 Device would be blocked");
        println!("   With USB_DEVICE_MONITOR: 👀 Device would be monitored");
        println!("   With USB_BLOCK_EXECUTABLES: ⚠️  Executable files would be blocked");
        println!("   With USB_DETECT_SUSPICIOUS: 🔍 Suspicious files would be detected");
    }
    
    println!("\n✅ USB protection test completed");
    Ok(())
}

    /// View active policies
    async fn view_active_policies(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n{}", Style::new().bold().apply_to("📜 Active Policies"));
        
        if let Some(comm) = &self.communicator {
            match comm.get_agent_policies().await {
                Ok(policies) => {
                    let active_policies: Vec<_> = policies.iter().filter(|p| p.is_active).collect();
                    if active_policies.is_empty() {
                        println!("   No active policies");
                    } else {
                        for policy in active_policies {
                            println!("   • {} - {} ({})", policy.name, policy.description, policy.category);
                        }
                    }
                }
                Err(e) => {
                    println!("   Error loading policies: {}", e);
                }
            }
        }
        
        Ok(())
    }

    /// Send test alert
    async fn send_test_alert(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n📤 Sending test alert to server...");
        
        if let Some(comm) = &self.communicator {
            if let Some(token) = &comm.get_token() {
                let alert_data = serde_json::json!({
                    "agentId": self.agent_id,
                    "alertType": "TEST_ALERT",
                    "description": "Test alert from Rust agent GUI",
                    "severity": "MEDIUM",
                    "actionTaken": "TESTED"
                });
                
                match comm.send_alert(&alert_data, token).await {
                    Ok(_) => println!("✅ Test alert sent successfully!"),
                    Err(e) => println!("❌ Failed to send alert: {}", e),
                }
            }
        }
        
        Ok(())
    }

    /// Logout agent
    fn logout(&mut self) {
        self.agent_id = 0;
        self.token.clear();
        self.username.clear();
        self.password.clear();
        self.is_authenticated = false;
        self.communicator = None;
    }
}