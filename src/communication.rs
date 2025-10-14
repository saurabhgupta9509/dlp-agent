// communication.rs
// Handles all communication with the backend server

use serde::{Deserialize, Serialize};
use std::time::Duration;
use log;
use crate::capabilities::PolicyCapability;
use crate::config::BASE_URL;
// ===== DATA STRUCTURES =====

/// Response from authentication endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde(rename = "agentId")] 
    pub agent_id: u64,
    pub username: String,
    pub password: Option<String>,
    pub status: String,
    #[serde(rename = "userId")]  // ✅ Optional: include both for compatibility
    pub user_id: Option<u64>,

    pub token: String, 
}

/// Credentials stored for the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredentials {
    pub agent_id: u64,
    pub username: String,
    pub password: String,
    pub token: Option<String>,
}

/// Response from login endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    #[serde(rename = "agentId")] 
    pub agent_id: u64,
    pub username: String,
    pub role: String,
    pub token: String,
}

/// Response containing policies for the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    #[serde(rename = "agentId")] 
    pub agent_id: u64,
    pub policies: Vec<crate::policy_engine::Policy>,
    pub timestamp: u64,
}

/// Standard API response format from backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

// ===== MAIN COMMUNICATOR =====

/// Handles all HTTP communication with the backend server
#[derive(Clone)]
pub struct ServerCommunicator {
    client: reqwest::Client,  // HTTP client for making requests
    base_url: String,         // Base URL of the backend server
    pub credentials: Option<AgentCredentials>,  // Agent credentials
}

impl ServerCommunicator {
    /// Create a new ServerCommunicator with default settings
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            base_url:BASE_URL.to_string(),
            credentials: None,
        }
    }
    
    // ===== AUTHENTICATION METHODS =====
    
    /// Register agent with the backend server
    pub async fn agent_register(&mut self, hostname: &str, mac_address: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/register", self.base_url);
        
        log::info!("🔐 Registering agent with server...");
        
        let auth_data = serde_json::json!({
            "hostname": hostname,
            "macAddress": mac_address
        });
    
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&auth_data)
            .send()
            .await?;
            
        let raw_response = response.text().await?;
        log::debug!("Raw registration response: {}", raw_response);
        
        match serde_json::from_str::<ApiResponse<AuthResponse>>(&raw_response) {
            Ok(api_response) => {
                if api_response.success {
                    if let Some(data) = api_response.data {
                        let password = data.password.unwrap_or_else(|| {
                            log::warn!("Password is null, generating fallback");
                            "default_password".to_string()
                        });
                        
                        self.credentials = Some(AgentCredentials {
                            agent_id: data.agent_id,
                            username: data.username.clone(),
                            password: password.clone(),
                            token: None,
                        });
                        
                        log::info!("🔐 Credentials stored - Username: {}, Password: {}", data.username, password);
                        return Ok(());
                    }
                }
                Err(format!("Registration failed: {}", api_response.message).into())
            }
            Err(e) => {
                log::error!("Failed to parse registration response: {}", e);
                log::error!("Response was: {}", raw_response);
                Err(format!("Invalid server response: {}", e).into())
            }
        }
    }
    
    /// Login agent with credentials
    pub async fn agent_login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/login", self.base_url);
        
        if let Some(creds) = &self.credentials {
            let auth_data = serde_json::json!({
                "username": creds.username,
                "password": creds.password
            });
    
            let response = self.client
                .post(&url)
                // .header("Content-Type", "application/json")
                .json(&auth_data)
                .send()
                .await?;
                
            let status = response.status();
            log::debug!("Login response status: {}", status);
            
            let raw_response = response.text().await?;
            log::debug!("Raw login response: {}", raw_response);
            
            if status.is_success() {
                // ✅ First try parsing with the new structure (agentId)
                match serde_json::from_str::<ApiResponse<AuthResponse>>(&raw_response) {
                    Ok(api_response) => {
                        if api_response.success {
                            if let Some(data) = api_response.data {
                                if let Some(mut creds) = self.credentials.take() {
                                    creds.agent_id = data.agent_id;
                                    creds.token = Some(data.token);
                                    self.credentials = Some(creds);
                                }
                                
                                log::info!("✅ Agent logged in successfully! Agent ID: {}", data.agent_id);
                                return Ok(());
                            }
                        } else {
                            log::error!("Login API returned success=false: {}", api_response.message);
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to parse with AuthResponse, trying alternative parsing: {}", e);
                        // ✅ Fallback: Try alternative parsing if needed
                        self.try_alternative_login_parsing(&raw_response).await?;
                    }
                }
            } else {
                log::error!("Login HTTP error: {}", status);
                log::error!("Response body: {}", raw_response);
            }
        } else {
            log::error!("No credentials available for login");
        }
        
        Err("Agent login failed - check credentials and server response".into())
    }

    async fn try_alternative_login_parsing(&mut self, raw_response: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Try to manually extract fields from JSON
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(raw_response) {
            if let Some(data) = json_value.get("data") {
                if let (Some(agent_id), Some(token)) = (
                    data.get("agentId").and_then(|v| v.as_u64()),
                    data.get("token").and_then(|v| v.as_str())
                ) {
                    if let Some(mut creds) = self.credentials.take() {
                        creds.agent_id = agent_id;
                        creds.token = Some(token.to_string());
                        self.credentials = Some(creds);
                        log::info!("✅ Agent logged in via alternative parsing! Agent ID: {}", agent_id);
                        return Ok(());
                    }
                }
            }
        }
        
        Err("Alternative login parsing failed".into())
    }

    // ===== POLICY MANAGEMENT METHODS =====
    
    /// Report agent capabilities to backend
    pub async fn report_capabilities(
        &self, 
        agent_id: u64, 
        token: &str, 
        capabilities: &[PolicyCapability]
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/capabilities", self.base_url);
        
        let request_data = serde_json::json!({
            "agentId": agent_id,
            "capabilities": capabilities
        });
        println!("DEBUG: Sending JSON: {}", serde_json::to_string_pretty(&request_data)?);
        log::info!("📤 Reporting {} capabilities to backend...", capabilities.len());
        
        let response = self.client
            .post(&url)
            .header("Authorization", token)
            .header("Content-Type", "application/json")
            .json(&request_data)
            .send()
            .await?;
            
        if response.status().is_success() {
            log::info!("✅ Capabilities reported successfully");
            Ok(())
        } else {
            let error_text = response.text().await?;
            log::error!("❌ Failed to report capabilities: {}", error_text);
            Err(format!("Failed to report capabilities: {}", error_text).into())
        }
    }
    
    /// Get active policies assigned to this agent
    pub async fn get_active_policies(
        &self, 
        agent_id: u64, 
        token: &str
    ) -> Result<Vec<crate::policy_engine::Policy>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/active-policies?agentId={}", self.base_url, agent_id);
        
        let response = self.client
            .get(&url)
            .header("Authorization", token)
            .send()
            .await?;
            
        if response.status().is_success() {
            let api_response: ApiResponse<PolicyResponse> = response.json().await?;
            if api_response.success {
                if let Some(data) = api_response.data {
                    log::info!("📋 Received {} active policies from backend", data.policies.len());
                    return Ok(data.policies);
                }
            }
        }
        
        log::warn!("⚠️ No active policies received from backend");
        Ok(vec![]) // Return empty if no policies
    }
    
    /// Get all agent policies (legacy method)
    pub async fn get_agent_policies(&self) -> Result<Vec<crate::policy_engine::Policy>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/policies", self.base_url);
        
        if let Some(creds) = &self.credentials {
            if let Some(token) = &creds.token {
                let response = self.client
                    .get(&url)
                    .header("Authorization", token)
                    .send()
                    .await?;
                    
                if response.status().is_success() {
                    let api_response: ApiResponse<PolicyResponse> = response.json().await?;
                    if api_response.success {
                        if let Some(data) = api_response.data {
                            log::info!("✅ Retrieved {} policies", data.policies.len());
                            return Ok(data.policies);
                        }
                    }
                    Err(format!("Failed to get policies: {}", api_response.message).into())
                } else {
                    Err(format!("HTTP {}: Failed to get policies", response.status()).into())
                }
            } else {
                Err("No session token available - agent not logged in".into())
            }
        } else {
            Err("No credentials available - agent not registered".into())
        }
    }
    
    // ===== AGENT OPERATIONS =====
    
    /// Send heartbeat to backend
    pub async fn send_heartbeat(&self, agent_id: u64, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/heartbeat?agentId={}", self.base_url, agent_id);
        
        let response = self.client
            .post(&url)
            .header("Authorization", token)
            .send()
            .await?;
            
        if response.status().is_success() {
            log::debug!("💓 Heartbeat sent successfully");
            Ok(())
        } else {
            Err(format!("HTTP {}: Heartbeat failed", response.status()).into())
        }
    }
    
    /// Send alert to backend
    pub async fn send_alert(&self, alert_data: &serde_json::Value, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/alerts", self.base_url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", token)
            .json(alert_data)
            .send()
            .await?;
            
        if response.status().is_success() {
            log::debug!("📤 Alert sent successfully");
            Ok(())
        } else {
            Err(format!("HTTP {}: Alert sending failed", response.status()).into())
        }
    }
    
    /// Send USB-specific alert to backend
    pub async fn send_usb_alert(&self, usb_alert_data: &serde_json::Value, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/usb-alert", self.base_url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", token)
            .json(usb_alert_data)
            .send()
            .await?;
            
        if response.status().is_success() {
            log::info!("📤 USB alert sent successfully");
            Ok(())
        } else {
            Err(format!("HTTP {}: USB alert sending failed", response.status()).into())
        }
    }
    
    // ===== UTILITY METHODS =====
    
    /// Set credentials manually (for GUI login)
    pub fn set_credentials(&mut self, username: String, password: String) {
        self.credentials = Some(AgentCredentials {
            agent_id: 0,
            username,
            password,
            token: None,
        });
    }
    
    /// Get current credentials
    pub fn get_credentials(&self) -> Option<&AgentCredentials> {
        self.credentials.as_ref()
    }
    
    /// Get agent ID from credentials
    pub fn get_agent_id(&self) -> Option<u64> {
        self.credentials.as_ref().map(|creds| creds.agent_id)
    }
    
    /// Get token from credentials
    pub fn get_token(&self) -> Option<String> {
        self.credentials.as_ref().and_then(|creds| creds.token.clone())
    }
}