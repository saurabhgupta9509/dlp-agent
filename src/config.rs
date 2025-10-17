// config.rs
// Central configuration file for the DLP agent

use once_cell::sync::Lazy;

/// Default base URL for backend server
pub static BASE_URL: Lazy<String> = Lazy::new(|| {
    // In enterprise builds, this could be read from a config file or environment variable
    std::env::var("DLP_SERVER_URL").unwrap_or_else(|_| {
        // "http://10.180.30.73:8080".to_string()
        "http://192.168.1.127:8080".to_string()

    })
});

// Example of environment variable usage:
// export DLP_SERVER_URL=https://dlp-enterprise.mycompany.com:8443
