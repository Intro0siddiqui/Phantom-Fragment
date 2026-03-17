use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct OciConfig {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub process: Process,
    pub root: Root,
    pub hostname: String,
    pub mounts: Vec<Mount>,
    pub linux: Linux,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Process {
    pub terminal: bool,
    pub user: User,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Root {
    pub path: String,
    pub readonly: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    pub source: String,
    pub options: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Linux {
    pub namespaces: Vec<Namespace>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub ns_type: String,
}

impl Default for OciConfig {
    fn default() -> Self {
        Self {
            oci_version: "1.0.2".to_string(),
            process: Process {
                terminal: true,
                user: User { uid: 0, gid: 0 },
                args: vec!["sh".to_string()],
                env: vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                    "TERM=xterm".to_string(),
                ],
                cwd: "/".to_string(),
            },
            root: Root {
                path: "rootfs".to_string(),
                readonly: false,
            },
            hostname: "phantom".to_string(),
            mounts: vec![
                Mount {
                    destination: "/proc".to_string(),
                    mount_type: "proc".to_string(),
                    source: "proc".to_string(),
                    options: vec![],
                },
                Mount {
                    destination: "/dev".to_string(),
                    mount_type: "tmpfs".to_string(),
                    source: "tmpfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "strictatime".to_string(),
                        "mode=755".to_string(),
                        "size=65536k".to_string(),
                    ],
                },
            ],
            linux: Linux {
                namespaces: vec![
                    Namespace {
                        ns_type: "pid".to_string(),
                    },
                    Namespace {
                        ns_type: "network".to_string(),
                    },
                    Namespace {
                        ns_type: "ipc".to_string(),
                    },
                    Namespace {
                        ns_type: "uts".to_string(),
                    },
                    Namespace {
                        ns_type: "mount".to_string(),
                    },
                ],
            },
        }
    }
}
