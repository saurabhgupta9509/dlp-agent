// // main.rs
// // Main entry point for the DLP Agent application

// use dlp_agent::{AgentGUI, AgentCore};
// use std::error::Error;

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn Error>> {
//     // Initialize logger
//     env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
//     log::info!("🚀 Starting DLP Protection Agent...");
//     log::info!("Version: 1.0.0");
//     log::info!("Backend: http://localhost:8080");

//     // Create and run GUI for authentication
//     let mut gui = AgentGUI::new();
//     gui.run_authentication_only().await?; // We will create this new function
//     // Run GUI - this will handle authentication
//     if let Err(e) = gui.run().await {
//         log::error!("❌ GUI error: {}", e);
//         return Err(e);
//     }

//     // If authentication was successful, start protection services
//     if gui.is_authenticated {
//         log::info!("✅ Authentication successful, starting protection services...");
        
//         if let Some(communicator) = gui.communicator {
//             // Create agent core
//             let mut agent_core = AgentCore::new();
            
//             // Transfer authentication from GUI to agent core
//             agent_core.communicator = communicator;
//             agent_core.agent_id = gui.agent_id;


//             agent_core.token = format!("Bearer {}", gui.token);
//             if agent_core.token.is_empty() {
//                 return Err("Login successful, but no token was set.".into());
//            }
//             log::info!("🎯 Agent ID: {}", agent_core.agent_id);
//             log::info!("🖥️  Hostname: {}", agent_core.config.hostname);
//             log::info!("📡 MAC Address: {}", agent_core.config.mac_address);
            
//             // Initialize agent core (report capabilities, fetch policies)
//             if let Err(e) = agent_core.initialize().await {
//                 log::error!("❌ Agent initialization failed: {}", e);
//                 return Err(e);
//             }
            
//             log::info!("✅ Agent core initialized successfully");
//             log::info!("📋 Active policies: {}", agent_core.get_active_policies_info());
            
//             // Start the main protection loop (runs forever)
//             log::info!("🔄 Starting main protection loop...");
//             if let Err(e) = agent_core.run().await {
//                 log::error!("❌ Agent core error: {}", e);
//                 return Err(e);
//             }
//         } else {
//             log::error!("❌ No communicator available after login");
//             return Err("No communicator after login".into());
//         }
//     } else {
//         log::warn!("⚠️ Agent not authenticated, exiting");
//     }

//     Ok(())
// }
use dlp_agent::{AgentGUI, AgentCore};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("🚀 Starting DLP Protection Agent...");

    let mut gui = AgentGUI::new();
    gui.run_authentication_only().await?;

    if gui.is_authenticated {
        log::info!("✅ Authentication successful. Starting AgentCore service...");
        
        if let Some(communicator) = gui.communicator {
            let mut agent_core = AgentCore::new();
            
            agent_core.communicator = communicator;
            agent_core.agent_id = gui.agent_id;
            
            // THIS IS THE KEY CHANGE:
            // We format the token correctly with "Bearer " before giving it to the AgentCore.
            agent_core.token = format!("Bearer {}", gui.token);
            
            // Now, initialize the AgentCore. It will go straight to reporting capabilities.
            if let Err(e) = agent_core.initialize().await {
                log::error!("❌ AgentCore initialization failed: {}", e);
                return Err(e);
            }
            
            log::info!("✅ AgentCore initialized. Starting main protection loop...");
            
            if let Err(e) = agent_core.run().await {
                log::error!("❌ AgentCore run failed: {}", e);
                return Err(e);
            }
        } // ... (rest of the file is the same)
    } else {
        log::warn!("⚠️ Agent not authenticated. Exiting.");
    }

    Ok(())
}