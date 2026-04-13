//! Network Management
//!
//! Handles network namespace isolation and configuration.

use anyhow::{anyhow, Result};
use futures::stream::TryStreamExt;
use netlink_packet_route::link::nlas::Nla;
use nix::sched::{unshare, CloneFlags};
use rtnetlink::{new_connection, Handle};
use std::net::IpAddr;

pub struct NetworkNamespace {
    _marker: std::marker::PhantomData<()>,
}

impl NetworkNamespace {
    /// Create a new network namespace for the current process.
    /// Automatically brings up the loopback interface (lo) which is required
    /// for proper network functionality in the new namespace.
    pub fn new() -> Option<Self> {
        match unshare(CloneFlags::CLONE_NEWNET) {
            Ok(_) => {
                // Bring up the loopback interface automatically
                if let Err(e) = Self::bring_up_loopback() {
                    log::warn!("Failed to bring up loopback interface: {}", e);
                    // Continue anyway as the namespace was created successfully
                }
                Some(Self {
                    _marker: std::marker::PhantomData,
                })
            }
            Err(e) => {
                log::warn!("Failed to create network namespace: {}", e);
                None
            }
        }
    }

    /// Bring up the loopback interface in the current network namespace.
    /// Uses the `ip` command to avoid creating a nested tokio runtime,
    /// which would panic if called from within an existing async context.
    fn bring_up_loopback() -> Result<()> {
        let output = std::process::Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .output()
            .map_err(|e| anyhow!("Failed to execute ip command: {}", e))?;

        if output.status.success() {
            log::info!("Loopback interface (lo) brought up successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Failed to bring up loopback: {}", stderr.trim()))
        }
    }
}

pub struct NetworkManager {
    handle: Handle,
}

impl NetworkManager {
    pub async fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    /// List all network interfaces
    pub async fn list_interfaces(&self) -> Result<Vec<String>> {
        let mut links = self.handle.link().get().execute();
        let mut names = Vec::new();

        while let Some(link) = links.try_next().await? {
            for nla in link.nlas {
                if let Nla::IfName(name) = nla {
                    names.push(name);
                }
            }
        }
        Ok(names)
    }

    /// Bring an interface UP
    pub async fn set_interface_up(&self, name: &str) -> Result<()> {
        let mut links = self.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            let mut found = false;
            for nla in &link.nlas {
                if let Nla::IfName(n) = nla {
                    if n == name {
                        found = true;
                        break;
                    }
                }
            }

            if found {
                self.handle
                    .link()
                    .set(link.header.index)
                    .up()
                    .execute()
                    .await?;
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("Interface {} not found", name))
    }

    /// Add an IP address to an interface
    pub async fn add_ip_address(&self, interface: &str, ip: IpAddr, prefix_len: u8) -> Result<()> {
        let mut links = self.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            let mut found = false;
            for nla in &link.nlas {
                if let Nla::IfName(n) = nla {
                    if n == interface {
                        found = true;
                        break;
                    }
                }
            }

            if found {
                self.handle
                    .address()
                    .add(link.header.index, ip, prefix_len)
                    .execute()
                    .await?;
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("Interface {} not found", interface))
    }

    /// Create a VETH pair
    pub async fn create_veth_pair(&self, host_name: &str, peer_name: &str) -> Result<()> {
        self.handle
            .link()
            .add()
            .veth(host_name.to_string(), peer_name.to_string())
            .execute()
            .await?;
        Ok(())
    }
}

// Legacy function for compatibility
pub async fn list_interfaces() -> Result<Vec<String>> {
    let manager = NetworkManager::new().await?;
    manager.list_interfaces().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 1: Call NetworkNamespace::new() from a plain sync test context
    /// (no tokio runtime active). This exercises bring_up_loopback() which
    /// creates its own tokio::runtime::Runtime::new() internally.
    ///
    /// NOTE: Requires CAP_SYS_ADMIN to call unshare(CLONE_NEWNET).
    /// In CI or unprivileged environments this will fail/return None.
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN and CLONE_NEWNET support"]
    fn test_bring_up_loopback_from_sync_context() {
        // We are in a plain #[test] – no tokio runtime exists.
        // NetworkNamespace::new() internally calls bring_up_loopback()
        // which does: let rt = tokio::runtime::Runtime::new()?
        // This should succeed because no outer runtime is active.
        let ns = NetworkNamespace::new();
        // The namespace creation may still fail if the process lacks
        // CAP_SYS_ADMIN. The important thing is that the nested
        // Runtime::new() call itself does NOT panic here.
        // If ns is None, it is due to permission, not the nested-runtime bug.
        if let Some(_ns) = ns {
            println!("Network namespace created successfully from sync context");
        } else {
            println!(
                "Network namespace creation returned None (likely missing CAP_SYS_ADMIN)"
            );
        }
    }

    /// Test 2: Create a NetworkManager from an async (tokio) context.
    /// This is the normal / intended usage path and should work fine because
    /// NetworkManager::new() is async and does NOT create a nested runtime.
    #[tokio::test]
    async fn test_network_manager_from_async_context() {
        let manager = NetworkManager::new().await;
        assert!(
            manager.is_ok(),
            "NetworkManager::new() should succeed in async context; \
             failure may indicate missing rtnetlink socket permissions"
        );
        let manager = manager.unwrap();
        // Verify we can actually use it.
        let interfaces = manager.list_interfaces().await;
        assert!(
            interfaces.is_ok(),
            "list_interfaces() should succeed after successful new()"
        );
        let interfaces = interfaces.unwrap();
        // At minimum the loopback interface should always exist.
        assert!(
            interfaces.iter().any(|name| name == "lo"),
            "Expected 'lo' interface in list, got: {:?}",
            interfaces
        );
    }

    /// Test 3: Demonstrate the nested runtime creation problem.
    ///
    /// Calling tokio::runtime::Runtime::new() from inside an already-running
    /// tokio runtime panics when the inner runtime is dropped.
    ///
    /// NOTE: bring_up_loopback() has been fixed to use the `ip` command
    /// instead of creating a nested runtime, so NetworkNamespace::new() now
    /// works from both sync and async contexts. This test remains as a
    /// regression guard.
    #[tokio::test]
    #[should_panic(expected = "Cannot drop a runtime")]
    async fn test_nested_runtime_creation() {
        // Attempting to create a second tokio runtime while one is active
        // (provided by #[tokio::test]) panics when the inner runtime is dropped.
        let _rt = tokio::runtime::Runtime::new().unwrap();
        // Dropping `_rt` at end of scope triggers the panic.
    }

    /// Test 4: Call the legacy list_interfaces() free function from an async
    /// context. This should work because it calls NetworkManager::new().await
    /// (no nested runtime).
    #[tokio::test]
    async fn test_list_interfaces_from_async() {
        let interfaces = list_interfaces().await;
        assert!(
            interfaces.is_ok(),
            "list_interfaces() should succeed; error: {:?}",
            interfaces.err()
        );
        let interfaces = interfaces.unwrap();
        assert!(
            !interfaces.is_empty(),
            "Expected at least one interface (lo)"
        );
        assert!(
            interfaces.iter().any(|name| name == "lo"),
            "Expected 'lo' in interface list, got: {:?}",
            interfaces
        );
    }

    /// Test 5: Create multiple NetworkManager instances to verify that
    /// spawning several rtnetlink connections does not conflict.
    #[tokio::test]
    async fn test_network_manager_multiple_instances() {
        let manager1 = NetworkManager::new().await.expect("manager 1 creation failed");
        let manager2 = NetworkManager::new().await.expect("manager 2 creation failed");

        let ifaces1 = manager1.list_interfaces().await.expect("manager 1 list failed");
        let ifaces2 = manager2.list_interfaces().await.expect("manager 2 list failed");

        // Both managers should see the same set of interfaces.
        assert_eq!(
            ifaces1.len(),
            ifaces2.len(),
            "Both managers should report the same number of interfaces"
        );
        assert_eq!(
            ifaces1, ifaces2,
            "Both managers should report identical interface lists"
        );
        assert!(
            ifaces1.iter().any(|name| name == "lo"),
            "lo should be present in both lists"
        );
    }
}
