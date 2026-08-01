use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use velvet_rope_proxy::{PermitEpochProvider, hash_identifier};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochState {
    pub subgoal: String,
    pub subgoal_id_hash: String,
    pub epoch: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTable {
    by_subgoal_hash: BTreeMap<String, EpochState>,
}

impl EpochTable {
    pub fn current(&self, subgoal: &str) -> u64 {
        let subgoal_id_hash = hash_identifier(subgoal);
        self.by_subgoal_hash
            .get(&subgoal_id_hash)
            .map(|state| state.epoch)
            .unwrap_or(0)
    }

    pub fn current_for_subgoal_hash(&self, subgoal_id_hash: &str) -> Option<u64> {
        self.by_subgoal_hash
            .get(subgoal_id_hash)
            .map(|state| state.epoch)
    }

    pub fn activate(&mut self, subgoal: &str) -> String {
        let subgoal_id_hash = hash_identifier(subgoal);
        let state = self
            .by_subgoal_hash
            .entry(subgoal_id_hash.clone())
            .or_insert_with(|| EpochState {
                subgoal: subgoal.to_string(),
                subgoal_id_hash: subgoal_id_hash.clone(),
                epoch: 0,
                active: false,
            });
        state.active = true;
        subgoal_id_hash
    }

    pub fn is_active(&self, subgoal: &str) -> bool {
        let subgoal_id_hash = hash_identifier(subgoal);
        self.by_subgoal_hash
            .get(&subgoal_id_hash)
            .is_some_and(|state| state.active)
    }

    pub fn is_active_hash(&self, subgoal_id_hash: &str) -> bool {
        self.by_subgoal_hash
            .get(subgoal_id_hash)
            .is_some_and(|state| state.active)
    }

    pub fn advance(&mut self, subgoal: &str) -> Result<(u64, u64)> {
        let subgoal_id_hash = hash_identifier(subgoal);
        let state = self
            .by_subgoal_hash
            .entry(subgoal_id_hash.clone())
            .or_insert_with(|| EpochState {
                subgoal: subgoal.to_string(),
                subgoal_id_hash,
                epoch: 0,
                active: false,
            });
        let previous = state.epoch;
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow!("subgoal epoch overflow"))?;
        state.active = false;
        Ok((previous, state.epoch))
    }

    pub fn deactivate(&mut self, subgoal: &str) {
        let subgoal_id_hash = hash_identifier(subgoal);
        if let Some(state) = self.by_subgoal_hash.get_mut(&subgoal_id_hash) {
            state.active = false;
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SynchronizedEpochTable {
    inner: Arc<RwLock<EpochTable>>,
}

impl SynchronizedEpochTable {
    pub fn new(table: EpochTable) -> Self {
        Self {
            inner: Arc::new(RwLock::new(table)),
        }
    }

    pub fn current(&self, subgoal: &str) -> Result<u64> {
        Ok(self
            .inner
            .read()
            .map_err(|_| anyhow!("epoch table lock poisoned"))?
            .current(subgoal))
    }

    pub fn activate(&self, subgoal: &str) -> Result<String> {
        Ok(self
            .inner
            .write()
            .map_err(|_| anyhow!("epoch table lock poisoned"))?
            .activate(subgoal))
    }

    pub fn advance(&self, subgoal: &str) -> Result<(u64, u64)> {
        self.inner
            .write()
            .map_err(|_| anyhow!("epoch table lock poisoned"))?
            .advance(subgoal)
    }

    pub fn is_active(&self, subgoal: &str) -> Result<bool> {
        Ok(self
            .inner
            .read()
            .map_err(|_| anyhow!("epoch table lock poisoned"))?
            .is_active(subgoal))
    }

    pub fn is_active_hash(&self, subgoal_id_hash: &str) -> Result<bool> {
        Ok(self
            .inner
            .read()
            .map_err(|_| anyhow!("epoch table lock poisoned"))?
            .is_active_hash(subgoal_id_hash))
    }

    pub fn logical_step_for_subgoal(&self, subgoal: &str) -> Result<i64> {
        let epoch = self.current(subgoal)?;
        i64::try_from(epoch).map_err(|_| anyhow!("subgoal epoch exceeds permit logical-step range"))
    }
}

impl PermitEpochProvider for SynchronizedEpochTable {
    fn current_epoch_for_subgoal_hash(&self, subgoal_id_hash: &str) -> Result<i64> {
        let guard = self
            .inner
            .read()
            .map_err(|_| anyhow!("epoch table lock poisoned"))?;
        let epoch = guard
            .current_for_subgoal_hash(subgoal_id_hash)
            .ok_or_else(|| anyhow!("logical-step permit references inactive subgoal"))?;
        if !guard.is_active_hash(subgoal_id_hash) {
            bail!("logical-step permit references closed subgoal");
        }
        i64::try_from(epoch).map_err(|_| anyhow!("subgoal epoch exceeds permit logical-step range"))
    }
}
