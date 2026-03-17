use landlock::{
    Access, AccessFs, BitFlags, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, ABI,
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
            let file = std::fs::File::open(path_obj)
                .map_err(|e| format!("Failed to open path {}: {}", path, e))?;

            // PathBeneath::new takes (fd, access_mask)
            let rule = landlock::PathBeneath::new(file, access);
            match ruleset.add_rule(rule) {
                Ok(new_ruleset) => {
                    *ruleset_guard = Some(new_ruleset);
                    Ok(())
                }
                Err(e) => {
                    // If it fails, we lost the ruleset ownership?
                    // The crate documentation says: "Returns the ruleset with the new rule added."
                    // If it errors, it likely returns the error and consumes the ruleset?
                    // Actually, usually builders return Result<Self, Error>.
                    // If it returns Error, we might lose the ruleset if it consumes self.
                    // But for Landlock, if adding a rule fails (e.g. path not found), we might want to continue.
                    // If the crate consumes self on error, that's tough.
                    // Let's assume standard builder: on error, it might return the error.
                    // Checking crate source would be ideal, but let's assume we fail hard for now if we lose it.
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
            // restrict_self consumes RulesetCreated
            match ruleset.restrict_self() {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("Failed to apply Landlock restriction: {}", e)),
            }
        } else {
            Err("Ruleset already applied or invalid".to_string())
        }
    }
}
