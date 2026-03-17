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
    /// Uses a blocking runtime since this is called from synchronous contexts.
    fn bring_up_loopback() -> Result<()> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| anyhow!("Failed to create tokio runtime: {}", e))?;

        rt.block_on(async {
            let (connection, handle, _) = new_connection()?;
            tokio::spawn(connection);

            let mut links = handle.link().get().execute();
            while let Some(link) = links.try_next().await? {
                let mut is_loopback = false;
                for nla in &link.nlas {
                    if let Nla::IfName(name) = nla {
                        if name == "lo" {
                            is_loopback = true;
                            break;
                        }
                    }
                }

                if is_loopback {
                    handle.link().set(link.header.index).up().execute().await?;
                    log::info!("Loopback interface (lo) brought up successfully");
                    return Ok(());
                }
            }
            Err(anyhow!("Loopback interface not found"))
        })
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
