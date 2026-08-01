use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use velvet_rope_proxy::{VERDICT_SAFE_KILL, verify_verdict_certificate_with_key};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskDecision {
    pub allow: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Value>,
}

pub trait RiskGate: Send + Sync {
    fn evaluate(
        &self,
        subgoal: &str,
        capability: &str,
        resource: &str,
        risk_class: Option<&str>,
    ) -> Result<RiskDecision>;
}

#[derive(Debug, Clone, Default)]
pub struct AllowRiskGate;

impl RiskGate for AllowRiskGate {
    fn evaluate(
        &self,
        _subgoal: &str,
        _capability: &str,
        _resource: &str,
        _risk_class: Option<&str>,
    ) -> Result<RiskDecision> {
        Ok(RiskDecision {
            allow: true,
            reason: "default allow".to_string(),
            certificate: None,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct MaxDeRiskGate {
    signed_envelope: Option<Value>,
}

impl MaxDeRiskGate {
    pub fn with_signed_envelope(signed_envelope: Value) -> Self {
        Self {
            signed_envelope: Some(signed_envelope),
        }
    }
}

impl RiskGate for MaxDeRiskGate {
    fn evaluate(
        &self,
        _subgoal: &str,
        _capability: &str,
        _resource: &str,
        risk_class: Option<&str>,
    ) -> Result<RiskDecision> {
        if risk_class != Some("irreversible") {
            return Ok(RiskDecision {
                allow: true,
                reason: "not high-risk".to_string(),
                certificate: None,
            });
        }
        let Some(envelope) = &self.signed_envelope else {
            return Ok(RiskDecision {
                allow: false,
                reason: "irreversible grants require a real signed Max-DE envelope".to_string(),
                certificate: None,
            });
        };
        Ok(RiskDecision {
            allow: true,
            reason: "signed Max-DE envelope supplied".to_string(),
            certificate: Some(envelope.clone()),
        })
    }
}

/// Risk gate that requires a Velvet-signed Verdict Certificate before any
/// irreversible grant.
///
/// No verdict math runs here: the gate only verifies the certificate's schema
/// constants, canonical payload hash, signing purpose, Ed25519 signature
/// against a pinned 32-byte public key supplied at construction, `verdict ==
/// "safe_kill"`, and expiry against an injectable clock (so tests control
/// time). Non-irreversible grants are allowed through untouched.
pub struct VerdictRiskGate {
    certificate: Option<Value>,
    verifying_key_bytes: [u8; 32],
    clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

impl std::fmt::Debug for VerdictRiskGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerdictRiskGate")
            .field("certificate", &self.certificate)
            .field("verifying_key_bytes", &self.verifying_key_bytes)
            .finish_non_exhaustive()
    }
}

impl VerdictRiskGate {
    /// Build a gate pinned to the trusted verdict-signing public key.
    pub fn new(verifying_key_bytes: [u8; 32]) -> Self {
        Self {
            certificate: None,
            verifying_key_bytes,
            clock: Arc::new(Utc::now),
        }
    }

    /// Supply the verdict certificate presented for irreversible grants.
    pub fn with_certificate(mut self, certificate: Value) -> Self {
        self.certificate = Some(certificate);
        self
    }

    /// Override the clock used for expiry checks (tests control time).
    pub fn with_clock(mut self, clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }
}

impl RiskGate for VerdictRiskGate {
    fn evaluate(
        &self,
        _subgoal: &str,
        _capability: &str,
        _resource: &str,
        risk_class: Option<&str>,
    ) -> Result<RiskDecision> {
        if risk_class != Some("irreversible") {
            return Ok(RiskDecision {
                allow: true,
                reason: "not irreversible".to_string(),
                certificate: None,
            });
        }
        let deny = |reason: &str| {
            Ok(RiskDecision {
                allow: false,
                reason: reason.to_string(),
                certificate: None,
            })
        };
        let Some(certificate) = &self.certificate else {
            return deny("irreversible grants require a valid verdict certificate");
        };
        let now = (self.clock)();
        match verify_verdict_certificate_with_key(certificate, &self.verifying_key_bytes, None, now)
        {
            Err(_) => deny("irreversible grants require a valid verdict certificate"),
            Ok(check) if check.expired => deny("verdict_expired_requires_inspection"),
            Ok(check) if check.verdict != VERDICT_SAFE_KILL => deny("verdict_not_safe_kill"),
            Ok(_) => Ok(RiskDecision {
                allow: true,
                reason: "verdict certificate verified: safe_kill".to_string(),
                certificate: Some(certificate.clone()),
            }),
        }
    }
}
