use caps::{CapSet, Capability};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CapabilityError {
    #[error("Caps error: {0}")]
    Caps(#[from] caps::errors::CapsError),
    #[error("Invalid capability: {0}")]
    InvalidCap(String),
}

pub fn drop_capabilities(caps_to_drop: &[&str]) -> Result<(), CapabilityError> {
    for cap_str in caps_to_drop {
        let upper = cap_str.to_uppercase();
        // Ensure CAP_ prefix for parsing
        let cap_name = if upper.starts_with("CAP_") {
            upper
        } else {
            format!("CAP_{}", upper)
        };

        let cap = Capability::from_str(&cap_name)
            .map_err(|_| CapabilityError::InvalidCap(cap_str.to_string()))?;

        // Attempt to drop from all sets.
        // Log errors but continue - we may not have the capability to begin with.
        if let Err(e) = caps::drop(None, CapSet::Effective, cap) {
            log::warn!("Failed to drop effective capability {}: {}", cap_name, e);
        }
        if let Err(e) = caps::drop(None, CapSet::Permitted, cap) {
            log::warn!("Failed to drop permitted capability {}: {}", cap_name, e);
        }
        if let Err(e) = caps::drop(None, CapSet::Inheritable, cap) {
            log::warn!("Failed to drop inheritable capability {}: {}", cap_name, e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_drop_capabilities_dummy() {
        // Requires privileges or actual caps
        let _ = drop_capabilities(&["cap_sys_admin"]);
    }
}
