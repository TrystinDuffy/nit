#[cfg(not(target_os = "macos"))]
use anyhow::bail;
use anyhow::Result;

use crate::identity::{DeviceIdentity, DiscoveredIdentity, IdentityBackend, IdentitySession};

#[cfg(test)]
pub mod test_identity;
#[cfg(target_os = "macos")]
pub mod touch_id;
pub mod yubikey;

pub fn provision(identity: &DiscoveredIdentity) -> Result<DeviceIdentity> {
    match identity.backend {
        IdentityBackend::YubiKey => yubikey::provision(identity),
        #[cfg(target_os = "macos")]
        IdentityBackend::TouchId => touch_id::provision(identity),
        #[cfg(not(target_os = "macos"))]
        IdentityBackend::TouchId => bail!("Touch ID is available only on macOS"),
    }
}

pub fn open(identity: &DiscoveredIdentity) -> Result<Box<dyn IdentitySession>> {
    match identity.backend {
        IdentityBackend::YubiKey => yubikey::open(identity),
        #[cfg(target_os = "macos")]
        IdentityBackend::TouchId => touch_id::open(identity),
        #[cfg(not(target_os = "macos"))]
        IdentityBackend::TouchId => bail!("Touch ID is available only on macOS"),
    }
}
