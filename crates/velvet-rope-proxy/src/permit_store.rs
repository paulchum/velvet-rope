use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use velvet_core::{DispatchClaim, ExecutionPermit};

use crate::ledger::{canonical_json, sha256_hex};

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct PermitClaimStore {
    root: PathBuf,
}

impl PermitClaimStore {
    #[doc(hidden)]
    pub fn for_ledger_path(path: &Path) -> Self {
        Self {
            root: path.with_extension("permit_claims"),
        }
    }

    #[doc(hidden)]
    pub fn issue(&self, permit: &ExecutionPermit) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("create permit claim store {}", self.root.display()))?;
        let path = self.root.join(format!("{}.issued.json", permit.permit_id));
        if path.exists() {
            return Ok(());
        }
        let payload = json!({
            "permit_id": permit.permit_id,
            "permit_hash": permit.permit_hash,
            "tenant_id": permit.tenant_id,
            "environment": permit.environment,
            "state": "issued",
            "issued_at": permit.validity.issued_at,
        });
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(mut file) => {
                file.write_all(canonical_json(&payload).as_bytes())?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("write issued permit state {}", path.display()))
            }
        }
    }

    #[doc(hidden)]
    pub fn claim(
        &self,
        permit: &ExecutionPermit,
        claimant: &str,
        claimed_at: &str,
    ) -> Result<Option<DispatchClaim>> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("create permit claim store {}", self.root.display()))?;
        self.issue(permit)?;
        let mut claim = DispatchClaim {
            claim_id: format!(
                "vclaim_{}",
                &sha256_hex(
                    canonical_json(&json!({
                        "permit_id": permit.permit_id,
                        "permit_hash": permit.permit_hash,
                        "claimant": claimant,
                    }))
                    .as_bytes()
                )[..32]
            ),
            permit_id: permit.permit_id.clone(),
            permit_hash: permit.permit_hash.clone(),
            claimed_at: claimed_at.to_string(),
            claimant: claimant.to_string(),
            pre_execution_record_hash: permit.lineage.pre_execution_record.artifact_hash.clone(),
            claim_hash: String::new(),
        };
        let unsigned = json!({
            "claim_id": claim.claim_id,
            "permit_id": claim.permit_id,
            "permit_hash": claim.permit_hash,
            "claimed_at": claim.claimed_at,
            "claimant": claim.claimant,
            "pre_execution_record_hash": claim.pre_execution_record_hash,
        });
        claim.claim_hash = format!(
            "sha256:{}",
            sha256_hex(canonical_json(&unsigned).as_bytes())
        );
        let path = self.root.join(format!("{}.claimed.json", permit.permit_id));
        let payload = json!({
            "state": "claimed",
            "claim": claim,
        });
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(mut file) => {
                file.write_all(canonical_json(&payload).as_bytes())?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                Ok(Some(claim))
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("write claimed permit state {}", path.display()))
            }
        }
    }

    #[doc(hidden)]
    pub fn complete(
        &self,
        permit: &ExecutionPermit,
        outcome: &str,
        receipt_hash: &str,
        completed_at: &str,
    ) -> Result<()> {
        if !self
            .root
            .join(format!("{}.claimed.json", permit.permit_id))
            .exists()
        {
            return Err(anyhow!("cannot complete unclaimed execution permit"));
        }
        let path = self
            .root
            .join(format!("{}.{}.json", permit.permit_id, outcome));
        let payload = json!({
            "permit_id": permit.permit_id,
            "permit_hash": permit.permit_hash,
            "state": outcome,
            "receipt_hash": receipt_hash,
            "completed_at": completed_at,
        });
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(mut file) => {
                file.write_all(canonical_json(&payload).as_bytes())?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("write terminal permit state {}", path.display())),
        }
    }

    #[allow(dead_code)]
    #[doc(hidden)]
    pub fn claimed_record(&self, permit_id: &str) -> Result<Option<Value>> {
        let path = self.root.join(format!("{permit_id}.claimed.json"));
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("read permit claim {}", path.display()))?;
        Ok(Some(serde_json::from_str(&text)?))
    }
}
