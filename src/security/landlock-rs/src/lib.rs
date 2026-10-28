use landlock::{
    Access, AccessFs, BitFlags, RestrictSelfAttr, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetError, RulesetStatus, ABI,
};
use parking_lot::Mutex;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LandlockError {
    #[error("Landlock not supported by kernel")]
    NotSupported,
    #[error("Failed to create ruleset: {0}")]
    RulesetCreation(#[from] RulesetError),
    #[error("Failed to add rule: {0}")]
    AddRule(String),
    #[error("Failed to restrict self: {0}")]
    Restriction(String),
}

const ACCESS_WRITE: u64 = 0x2;
const ACCESS_EXECUTE: u64 = 0x4;

fn access_rights_to_flags(access_rights: u64) -> BitFlags<AccessFs> {
    let mut access: BitFlags<AccessFs> = AccessFs::ReadFile.into();

    if access_rights & ACCESS_EXECUTE != 0 {
        access |= AccessFs::Execute;
    }
    if access_rights & ACCESS_WRITE != 0 {
        access |= AccessFs::WriteFile;
    }

    if access.is_empty() {
        access = AccessFs::ReadFile | AccessFs::Execute;
    }

    access
}

pub struct LandlockContext {
    // Ruleset in landlock crate is a builder that consumes itself on add_rule.
    // We need to store it in a way we can update it.
    // Since add_rule returns a new Ruleset (or Result<Ruleset>), we need to swap it.
    ruleset: Mutex<Option<landlock::RulesetCreated>>,
}

impl LandlockContext {
    pub fn new() -> Option<Self> {
        let abi = ABI::V1;
        let access_fs = AccessFs::from_all(abi);

        // handle_access returns Result<RulesetAttr, RulesetError>
        let attr = match Ruleset::default().handle_access(access_fs) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Failed to configure Landlock ruleset: {}", e);
                return None;
            }
        };

        // create returns Result<RulesetCreated, RulesetError>
        let ruleset = match attr.create() {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Failed to create Landlock ruleset: {}", e);
                return None;
            }
        };

        Some(Self {
            ruleset: Mutex::new(Some(ruleset)),
        })
    }

    pub fn add_rule(&self, path: &str, access_rights: u64) -> Result<(), String> {
        let mut ruleset_guard = self.ruleset.lock();

        if let Some(ruleset) = ruleset_guard.take() {
            let path_obj = Path::new(path);
            let access = access_rights_to_flags(access_rights);

            // We need to open the path to get a file descriptor.
            // Landlock requires an open file descriptor to identify the object.
            let file = match std::fs::File::open(path_obj) {
                Ok(f) => f,
                Err(e) => {
                    // Put the ruleset back before returning error
                    *ruleset_guard = Some(ruleset);
                    return Err(format!("Failed to open path {}: {}", path, e));
                }
            };

            // PathBeneath::new takes (fd, access_mask)
            let rule = landlock::PathBeneath::new(file, access);
            match ruleset.add_rule(rule) {
                Ok(new_ruleset) => {
                    *ruleset_guard = Some(new_ruleset);
                    Ok(())
                }
                Err(e) => {
                    // In some builder patterns, if add_rule fails, the original ruleset
                    // might be lost if it was consumed. However, Landlock's Result usually
                    // doesn't return the original object on error.
                    // Given we can't easily recover the original ruleset if consumed,
                    // we log the fatal loss of context.
                    log::error!(
                        "CRITICAL: Ruleset lost due to add_rule failure for {}",
                        path
                    );
                    Err(format!("Failed to add rule for {}: {}", path, e))
                }
            }
        } else {
            Err("Ruleset already applied or invalid".to_string())
        }
    }

    pub fn apply(&self) -> Result<(), String> {
        let mut ruleset_guard = self.ruleset.lock();

        if let Some(ruleset) = ruleset_guard.take() {
            // Request process-wide enforcement (LANDLOCK_RESTRICT_SELF_TSYNC,
            // available since ABI v8). The crate's default CompatLevel is
            // BestEffort, so older kernels drop the flag instead of failing,
            // which preserves the previous thread-scoped behaviour.
            let ruleset = match ruleset.all_threads(true) {
                Ok(ruleset) => ruleset,
                Err(e) => {
                    return Err(format!(
                        "Failed to request all-thread Landlock restriction: {}",
                        e
                    ))
                }
            };

            // restrict_self consumes RulesetCreated
            match ruleset.restrict_self() {
                Ok(status) => {
                    if status.ruleset == RulesetStatus::NotEnforced {
                        log::warn!("Landlock ruleset was not enforced by the kernel");
                    } else if !status.all_threads {
                        log::warn!(
                            "Landlock TSYNC unavailable (kernel ABI < 8); \
                             only the calling thread is restricted"
                        );
                    }
                    Ok(())
                }
                Err(e) => Err(format!("Failed to apply Landlock restriction: {}", e)),
            }
        } else {
            Err("Ruleset already applied or invalid".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Temporary directory that removes itself when dropped.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("landlock-rs-{}-{}", label, std::process::id()));
            fs::create_dir_all(&path).expect("failed to create temporary directory");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn all_threads_flag_is_accepted() {
        let dir = TempDir::new("all-threads");
        let file = fs::File::open(&dir.0).expect("failed to open temporary directory");

        // Never call restrict_self() in a test: applying a ruleset would
        // restrict the test process (and, with TSYNC, every test thread).
        //
        // RulesetCreated does not expose requested_restrict_self_flags /
        // actual_restrict_self_flags, so the strongest available assertion is
        // that the builder accepts the request. On this kernel (ABI >= 8) the
        // TSYNC bit is recorded as applicable; on older kernels BestEffort
        // drops it instead of failing.
        let ruleset = Ruleset::default()
            .handle_access(AccessFs::Execute | AccessFs::ReadFile)
            .expect("failed to configure handled accesses")
            .create()
            .expect("failed to create ruleset")
            .add_rule(landlock::PathBeneath::new(file, AccessFs::ReadFile))
            .expect("failed to add rule")
            .all_threads(true)
            .expect("all_threads(true) should be accepted with BestEffort");

        drop(ruleset);
    }

    #[test]
    fn context_add_rule_succeeds() {
        let dir = TempDir::new("context-add-rule");
        let context = LandlockContext::new().expect("Landlock should be available on this kernel");

        context
            .add_rule(
                dir.0.to_str().expect("temporary directory is not UTF-8"),
                ACCESS_EXECUTE,
            )
            .expect("failed to add rule");
    }

    #[test]
    fn access_rights_map_to_flags() {
        assert!(access_rights_to_flags(0).contains(AccessFs::ReadFile));
        assert!(access_rights_to_flags(ACCESS_EXECUTE).contains(AccessFs::Execute));
        assert!(access_rights_to_flags(ACCESS_WRITE).contains(AccessFs::WriteFile));
    }
}
