use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;
use crate::protection_modules::ProtectionModule;
use crate::policy_constants::*;
use serde::Deserialize;
use std::collections::{BTreeSet, HashSet};
use std::net::ToSocketAddrs;
use log::{info, warn, error};
use std::hash::{Hash, Hasher};
use std::error::Error;
use std::ptr;
use std::mem;
use std::ffi::c_void; // Import c_void for raw pointers

// --- Windows Filtering Platform (WFP) Imports ---
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, RPC_E_RETRY};

use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineOpen0, FwpmEngineClose0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0,
    FWPM_SESSION0, FWPM_DISPLAY_DATA0, FWPM_SUBLAYER0, FWPM_FILTER0, FWPM_ACTION0,
    FWPM_FILTER_CONDITION0, FWP_V4_ADDR_AND_MASK, 
    // --- THIS IS THE FIX ---
    FWP_VALUE0, // We still need the base type for the range
    FWP_CONDITION_VALUE0, // The correct type for our condition
    FWP_CONDITION_VALUE0_0 as FWP_CONDITION_VALUE_UNION, // Give the union a clear name
    // --- END OF FIX ---
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWP_MATCH_EQUAL, FWPM_SUBLAYER_FLAG_PERSISTENT
};
use windows_sys::Win32::System::Rpc::{RpcMgmtWaitServerListen, RPC_C_AUTHN_WINNT};
use windows_sys::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

// --- THIS IS THE FIX for Send + Sync ---
// We create a new struct that holds the raw pointer.
// By implementing Send and Sync ourselves, we are telling Rust:
// "I promise it is safe to send this pointer between threads."
struct WfpHandle(*mut c_void);
unsafe impl Send for WfpHandle {}
unsafe impl Sync for WfpHandle {}
// --- END OF FIX ---

const DLP_AGENT_SUBLAYER_GUID: GUID = GUID {
    data1: 0x8a815a51, data2: 0x9303, data3: 0x4e8b, data4: [0x95, 0x2e, 0x48, 0x2e, 0x44, 0x5e, 0x76, 0x01],
};

#[derive(Deserialize, Debug, Clone, Default)]
struct NetworkPolicyData {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
}

// ===== NETWORK PROTECTION MODULE =====
pub struct NetworkProtection {
    // --- THIS IS THE FIX ---
    // The handle is now our thread-safe wrapper struct
    wfp_engine_handle: WfpHandle,
    // --- END OF FIX ---
    last_policy_hash: u64,
    active_filter_keys: Vec<GUID>,
}

impl NetworkProtection {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        info!("Initializing Network Protection Module (WFP)...");
        let result = unsafe { CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32) };
        if result < 0 {
            return Err(format!("Failed to initialize COM. Error code: {}", result).into());
        }
        let handle = Self::initialize_wfp_session()?;
        
        info!("✅ Network Protection Module connected to Windows Filtering Platform.");
        Ok(Self {
            wfp_engine_handle: WfpHandle(handle), // Store the raw pointer inside our wrapper
            last_policy_hash: 0,
            active_filter_keys: Vec::new(),
        })
    }

    async fn enforce_dns_policy(&mut self, policy_engine: &PolicyEngine) -> Result<(), Box<dyn Error>> {
        let policy_data: NetworkPolicyData = policy_engine.get_policy_json_data(POLICY_NETWORK_DNS_BLOCK);
        let mut new_blocked_entries = BTreeSet::new();
        for domain in policy_data.domains { new_blocked_entries.insert(domain); }
        for ip in policy_data.ips { new_blocked_entries.insert(ip); }

        let new_hash = {
            let mut s = std::hash::DefaultHasher::new();
            new_blocked_entries.hash(&mut s);
            std::hash::Hasher::finish(&s)
        };

        if new_hash == self.last_policy_hash {
            return Ok(());
        }

        info!("🛡️ New network policy detected. Applying WFP rules...");
        self.clear_wfp_rules()?;
        let ips_to_block = self.resolve_domains_to_ips(new_blocked_entries).await;
        info!("Resolved to {} unique IP addresses for blocking.", ips_to_block.len());

        for ip in &ips_to_block {
            match self.add_wfp_block_rule(ip) {
                Ok(filter_key) => self.active_filter_keys.push(filter_key),
                Err(e) => error!("Failed to add block rule for IP {}: {}", ip, e),
            }
        }
        
        self.last_policy_hash = new_hash;
        Ok(())
    }

    async fn resolve_domains_to_ips(&self, entries: BTreeSet<String>) -> HashSet<String> {
        let mut ips = HashSet::new();
        for entry in entries {
            if entry.parse::<std::net::IpAddr>().is_ok() {
                ips.insert(entry);
            } else {
                let addr_with_port = format!("{}:80", entry);
                if let Ok(addresses) = tokio::net::lookup_host(addr_with_port).await {
                    for addr in addresses {
                        if addr.is_ipv4() {
                            ips.insert(addr.ip().to_string());
                        }
                    }
                } else {
                    warn!("Could not resolve domain '{}'", entry);
                }
            }
        }
        ips
    }

    // --- LOW-LEVEL WFP HELPER FUNCTIONS ---

    fn initialize_wfp_session() -> Result<*mut c_void, Box<dyn Error>> {
        let mut session_name: Vec<u16> = "DLP Agent Session".encode_utf16().collect();
        session_name.push(0);
        let mut session_desc: Vec<u16> = "DLP agent session".encode_utf16().collect();
        session_desc.push(0);
        
        let mut session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 { 
                name: session_name.as_mut_ptr(), 
                description: session_desc.as_mut_ptr() 
            },
            // --- THIS IS THE FIX ---
            // This flag tells Windows to automatically clean up our rules if the agent crashes.
            flags: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION_FLAG_DYNAMIC,
            // --- END OF FIX ---
            ..Default::default()
        };

        let mut engine_handle: *mut c_void = ptr::null_mut();
        let result = unsafe {
            RpcMgmtWaitServerListen();
            FwpmEngineOpen0(ptr::null(), RPC_C_AUTHN_WINNT, ptr::null(), &session, &mut engine_handle)
        };

        if result as u32 != ERROR_SUCCESS {
            return Err(format!("WFP Connection Failed: {}. Are you running as Administrator?", result).into());
        }

        let mut sublayer_name: Vec<u16> = "DLP Agent SubLayer".encode_utf16().collect();
        sublayer_name.push(0);
        let mut sublayer_desc: Vec<u16> = "Sublayer for DLP agent network rules".encode_utf16().collect();
        sublayer_desc.push(0);

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: DLP_AGENT_SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: sublayer_name.as_mut_ptr(),
                description: sublayer_desc.as_mut_ptr(),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            weight: 0,
            ..Default::default()
        };

        let result = unsafe { FwpmSubLayerAdd0(engine_handle, &sublayer, ptr::null_mut()) }; // FIX: Use null_mut()
        if result as u32 != ERROR_SUCCESS {
            warn!("Failed to add WFP sublayer (it might already exist). Code: {}", result);
        }

        Ok(engine_handle)
    }

    fn clear_wfp_rules(&mut self) -> Result<(), Box<dyn Error>> {
        info!("Clearing {} old WFP rules...", self.active_filter_keys.len());
        for key in &self.active_filter_keys {
            let result = unsafe { FwpmFilterDeleteByKey0(self.wfp_engine_handle.0, key) }; // FIX: Use .0 to get the pointer
            if result as u32 != ERROR_SUCCESS {
                warn!("Failed to delete WFP filter. Code: {}", result);
            }
        }
        self.active_filter_keys.clear();
        Ok(())
    }

  /// Adds a single firewall rule to block all outbound traffic to a specific IP address.
  /// Adds a single firewall rule to block all outbound traffic to a specific IP address.
  fn add_wfp_block_rule(&self, ip_address: &str) -> Result<GUID, Box<dyn Error>> {
    let ip_addr: std::net::Ipv4Addr = ip_address.parse()?;
    let ip_addr_bytes = ip_addr.octets();

    let filter_key = unsafe {
        let mut guid = mem::zeroed();
        windows_sys::Win32::System::Com::CoCreateGuid(&mut guid);
        guid
    };

    let mut addr_mask = FWP_V4_ADDR_AND_MASK {
        addr: u32::from_be_bytes(ip_addr_bytes),
        mask: 0xFFFFFFFF,
    };
    
    // --- THIS IS THE FIX for the union field error ---
    // 1. Create a zeroed-out value of the CORRECT type: FWP_CONDITION_VALUE0
    let mut condition_value = FWP_CONDITION_VALUE0 { ..unsafe { mem::zeroed() } };
    
    // 2. Set the type so the C API knows which union field to read.
    condition_value.r#type = windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V4_ADDR_MASK;
    
    // 3. Use an unsafe block to write to the correct union field (`v4AddrMask`).
    unsafe {
        condition_value.Anonymous.v4AddrMask = &mut addr_mask;
    }
    // --- END OF FIX ---
    
    let mut filter_condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: condition_value, // No transmute needed now
    };

    let action = FWPM_ACTION0 { r#type: FWP_ACTION_BLOCK, ..unsafe { mem::zeroed() } };
    
    let mut filter_name: Vec<u16> = format!("DLP Block: {}", ip_address).encode_utf16().collect();
    filter_name.push(0);

    let mut filter = FWPM_FILTER0 {
        filterKey: filter_key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: filter_name.as_mut_ptr(),
            description: ptr::null_mut(),
        },
        layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        subLayerKey: DLP_AGENT_SUBLAYER_GUID,
        action,
        numFilterConditions: 1,
        filterCondition: &mut filter_condition,
        ..unsafe { mem::zeroed() }
    };

    let result = unsafe { FwpmFilterAdd0(self.wfp_engine_handle.0, &filter, ptr::null_mut(), ptr::null_mut()) };
    if result as u32 != ERROR_SUCCESS {
        return Err(format!("Failed to add WFP filter for {}. Error: {}", ip_address, result).into());
    }

    info!("✅ Added WFP block rule for IP: {}", ip_address);
    Ok(filter_key)
}

}

impl Drop for NetworkProtection {
    fn drop(&mut self) {
        if !self.wfp_engine_handle.0.is_null() { // FIX: Use .0
            info!("Shutting down Network Protection. Clearing rules and closing WFP handle...");
            if let Err(e) = self.clear_wfp_rules() {
                error!("Failed to clear WFP rules on shutdown: {}", e);
            }
            unsafe {
                FwpmSubLayerDeleteByKey0(self.wfp_engine_handle.0, &DLP_AGENT_SUBLAYER_GUID); // FIX: Use .0
                FwpmEngineClose0(self.wfp_engine_handle.0); // FIX: Use .0
                CoUninitialize();
            };
        }
    }
}

// ===== PROTECTION MODULE IMPLEMENTATION =====
#[async_trait::async_trait]
impl ProtectionModule for NetworkProtection {
    async fn execute(
        &mut self,
        policy_engine: &PolicyEngine,
        _communicator: &ServerCommunicator,
        _agent_id: u64,
        _token: &str
    ) -> Result<(), Box<dyn Error>> {
        
        if policy_engine.is_policy_active(POLICY_NETWORK_DNS_BLOCK) {
            self.enforce_dns_policy(policy_engine).await?;
        } else {
            if self.last_policy_hash != 0 {
                info!("🧹 Network policy disabled. Cleaning up WFP rules...");
                self.clear_wfp_rules()?;
                self.last_policy_hash = 0;
            }
        }
        Ok(())
    }

    fn get_name(&self) -> &str { "Network" }
}