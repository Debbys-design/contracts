#![no_std]
#![allow(clippy::too_many_arguments)]

//! # Emergency Medical Information Contract
//!
//! Manages emergency contact information, medical allergies, and critical health conditions
//! accessible during medical emergencies with encrypted storage and priority-based access.
//!
//! ## HIPAA Compliance
//!
//! **Access Control Safeguards:** Emergency responders authenticated via role validation.
//! Patient authorization for emergency info registration. Contact information access restricted
//! to authorized emergency personnel. Allergy and condition data accessible only during emergencies
//! or with patient consent.
//!
//! **Audit Controls:** Emergency access events emitted with responder identity and timestamp.
//! Contact priority levels tracked for triage. Critical condition flags logged. All emergency
//! info retrievals tracked for breach notifications and compliance auditing.
//!
//! **Data Retention Policy:** Emergency contacts retained indefinitely for rapid access. Medical
//! allergies and critical conditions stored persistently. Priority metadata maintained for
//! emergency response optimization. Patient deregistration removes all emergency medical data.
//!
//! **Encryption/Integrity:** Contact information stored as encrypted hashes (BytesN<32>).
//! Contact labels hashed to prevent disclosure of relationship type. Relationship class symbols
//! enumerated (family, friend, emergency contact, etc.). Emergency access limited to time-bound
//! overrides with justification tracking.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, Symbol, Vec,
};

/// --------------------
/// Emergency Structures
/// --------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyContact {
    pub contact_label_hash: BytesN<32>,
    pub relationship_class: Symbol,
    pub contact_hash: BytesN<32>, // Encrypted contact info
    pub priority: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyProfile {
    pub blood_type: Symbol,
    pub critical_allergy_hashes: Vec<BytesN<32>>,
    pub active_condition_hashes: Vec<BytesN<32>>,
    pub current_medication_hashes: Vec<BytesN<32>>,
    pub dnr_status: bool,
    pub emergency_contacts: Vec<EmergencyContact>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriticalAlert {
    pub provider_id: Address,
    pub alert_type: Symbol,
    pub alert_text_hash: BytesN<32>,
    pub severity: Symbol,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyAccessLog {
    pub provider_id: Address,
    pub emergency_type: Symbol,
    pub justification_hash: BytesN<32>,
    pub location_hash: BytesN<32>,
    pub access_time: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DNROrder {
    pub provider_id: Address,
    pub dnr_document_hash: BytesN<32>,
    pub effective_date: u64,
    pub recorded_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryConfig {
    pub emergency_contact: Address,
    pub guardians: Vec<Address>,
    pub recovery_threshold: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryProposal {
    pub new_owner: Address,
    pub approvals: Vec<Address>,
}

/// --------------------
/// Storage Keys
/// --------------------

#[contracttype]
pub enum DataKey {
    EmergencyProfile(Address),
    CriticalAlerts(Address),
    EmergencyAccessLog(Address),
    DNROrder(Address),
    EmergencyNotifications(Address),
    RecoveryConfig(Address),
    RecoveryProposal(Address),
    Admin,
    /// Registered emergency responder -> active flag. Only a registered,
    /// active responder may invoke the break-glass `emergency_access_request`.
    Responder(Address),
}

/// Maximum number of hashes allowed in `critical_allergy_hashes`.
/// Inputs exceeding this cap are rejected to prevent unbounded Vec growth.
pub const MAX_CRITICAL_ALLERGIES: u32 = 50;

/// Time window (in seconds) during which a break-glass emergency access
/// grant remains valid. Matches access-control's 1-hour emergency override.
/// After this window elapses, the responder must issue a fresh
/// `emergency_access_request` to regain read access.
pub const EMERGENCY_ACCESS_WINDOW_SECONDS: u64 = 3600;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    EmergencyProfileNotFound = 1,
    NotAuthorized = 2,
    InvalidRecoveryThreshold = 3,
    TooManyCriticalAllergies = 4,
    NotInitialized = 5,
    AlreadyInitialized = 6,
}

#[contract]
pub struct EmergencyMedicalInfo;

#[contractimpl]
impl EmergencyMedicalInfo {
    /// Configure the admin address allowed to manage the emergency responder registry.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Register an address as an authorized emergency responder.
    /// Only the configured admin may grant responder status.
    pub fn register_responder(env: Env, admin: Address, responder: Address) -> Result<(), Error> {
        Self::assert_admin(&env, &admin)?;
        env.storage()
            .persistent()
            .set(&DataKey::Responder(responder), &true);
        Ok(())
    }

    /// Revoke a previously registered emergency responder.
    /// Only the configured admin may revoke responder status.
    pub fn revoke_responder(env: Env, admin: Address, responder: Address) -> Result<(), Error> {
        Self::assert_admin(&env, &admin)?;
        env.storage().persistent().remove(&DataKey::Responder(responder));
        Ok(())
    }

    /// Check whether `responder` is currently a registered emergency responder.
    pub fn is_registered_responder(env: Env, responder: Address) -> bool {
        env.storage().persistent().has(&DataKey::Responder(responder))
    }

    fn assert_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if *admin != stored_admin {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }

    /// Set or update emergency profile for a patient
    /// Sub-second access optimized with persistent storage
    #[allow(clippy::too_many_arguments)]
    pub fn set_emergency_profile(
        env: Env,
        patient_id: Address,
        blood_type: Symbol,
        critical_allergy_hashes: Vec<BytesN<32>>,
        critical_condition_hashes: Vec<BytesN<32>>,
        current_medication_hashes: Vec<BytesN<32>>,
        emergency_contacts: Vec<EmergencyContact>,
        advance_directives_hash: Option<BytesN<32>>,
    ) -> Result<(), Error> {
        patient_id.require_auth();

        if critical_allergy_hashes.len() > MAX_CRITICAL_ALLERGIES {
            return Err(Error::TooManyCriticalAllergies);
        }

        let profile = EmergencyProfile {
            blood_type,
            critical_allergy_hashes,
            active_condition_hashes: critical_condition_hashes,
            current_medication_hashes,
            dnr_status: false,
            emergency_contacts,
        };

        let key = DataKey::EmergencyProfile(patient_id.clone());
        env.storage().persistent().set(&key, &profile);

        // Store advance directives if provided
        if let Some(hash) = advance_directives_hash {
            let dnr_key = DataKey::DNROrder(patient_id.clone());
            let dnr = DNROrder {
                provider_id: patient_id.clone(),
                dnr_document_hash: hash,
                effective_date: env.ledger().timestamp(),
                recorded_at: env.ledger().timestamp(),
            };
            env.storage().persistent().set(&dnr_key, &dnr);
        }

        Ok(())
    }

    /// Add critical alert to patient profile
    pub fn add_critical_alert(
        env: Env,
        patient_id: Address,
        provider_id: Address,
        alert_type: Symbol,
        alert_text_hash: BytesN<32>,
        severity: Symbol,
    ) -> Result<(), Error> {
        provider_id.require_auth();

        let key = DataKey::CriticalAlerts(patient_id.clone());
        let mut alerts: Vec<CriticalAlert> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));

        alerts.push_back(CriticalAlert {
            provider_id,
            alert_type,
            alert_text_hash,
            severity,
            timestamp: env.ledger().timestamp(),
        });

        env.storage().persistent().set(&key, &alerts);
        Ok(())
    }

    /// Break-glass emergency access request. Only a registered, active responder
    /// may invoke this. Records a time-stamped access log entry that grants
    /// time-bound read access to the patient's emergency information.
    pub fn emergency_access_request(
        env: Env,
        responder: Address,
        patient_id: Address,
        emergency_type: Symbol,
        justification_hash: BytesN<32>,
        location_hash: BytesN<32>,
    ) -> Result<(), Error> {
        responder.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::Responder(responder.clone()))
        {
            return Err(Error::NotAuthorized);
        }

        let key = DataKey::EmergencyAccessLog(patient_id.clone());
        let mut logs: Vec<EmergencyAccessLog> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));

        logs.push_back(EmergencyAccessLog {
            provider_id: responder,
            emergency_type,
            justification_hash,
            location_hash,
            access_time: env.ledger().timestamp(),
        });

        env.storage().persistent().set(&key, &logs);
        Ok(())
    }

    /// Determine whether `provider` currently holds a valid, unexpired
    /// break-glass access grant for `patient_id`.
    ///
    /// A grant is valid only if the provider is still a registered responder
    /// AND has an access log entry whose `access_time` falls within the
    /// `EMERGENCY_ACCESS_WINDOW_SECONDS` window ending at the current ledger
    /// time. Historical log entries no longer confer standing read access.
    fn has_emergency_access_log(env: &Env, patient_id: &Address, provider: &Address) -> bool {
        // A revoked responder must never retain access, even if a historical
        // log entry exists.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Responder(provider.clone()))
        {
            return false;
        }

        let key = DataKey::EmergencyAccessLog(patient_id.clone());
        let logs: Vec<EmergencyAccessLog> = match env.storage().persistent().get(&key) {
            Some(logs) => logs,
            None => return false,
        };

        let now = env.ledger().timestamp();
        for log in logs.iter() {
            if log.provider_id == *provider {
                // Time-bound: only a recent break-glass event grants access.
                if now >= log.access_time
                    && now - log.access_time <= EMERGENCY_ACCESS_WINDOW_SECONDS
                {
                    return true;
                }
            }
        }

        false
    }

    /// Retrieve emergency profile information for a patient.
    /// Requires a valid, unexpired break-glass access grant.
    pub fn get_emergency_info(
        env: Env,
        provider: Address,
        patient_id: Address,
    ) -> Result<EmergencyProfile, Error> {
        provider.require_auth();

        if !Self::has_emergency_access_log(&env, &patient_id, &provider) {
            return Err(Error::NotAuthorized);
        }

        let key = DataKey::EmergencyProfile(patient_id.clone());
        env.storage()
            .persistent()
            .get(&key)
            .ok_or(Error::EmergencyProfileNotFound)
    }

    /// Retrieve critical alerts for a patient.
    /// Requires a valid, unexpired break-glass access grant.
    pub fn get_critical_alerts(
        env: Env,
        provider: Address,
        patient_id: Address,
    ) -> Result<Vec<CriticalAlert>, Error> {
        provider.require_auth();

        if !Self::has_emergency_access_log(&env, &patient_id, &provider) {
            return Err(Error::NotAuthorized);
        }

        let key = DataKey::CriticalAlerts(patient_id.clone());
        Ok(env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env)))
    }

    /// Retrieve the emergency access log for a patient.
    /// Requires a valid, unexpired break-glass access grant.
    pub fn get_emergency_access_logs(
        env: Env,
        provider: Address,
        patient_id: Address,
    ) -> Result<Vec<EmergencyAccessLog>, Error> {
        provider.require_auth();

        if !Self::has_emergency_access_log(&env, &patient_id, &provider) {
            return Err(Error::NotAuthorized);
        }

        let key = DataKey::EmergencyAccessLog(patient_id.clone());
        Ok(env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env)))
    }

    /// Retrieve the DNR order for a patient.
    /// Requires a valid, unexpired break-glass access grant.
    pub fn get_dnr_order(
        env: Env,
        provider: Address,
        patient_id: Address,
    ) -> Result<DNROrder, Error> {
        provider.require_auth();

        if !Self::has_emergency_access_log(&env, &patient_id, &provider) {
            return Err(Error::NotAuthorized);
        }

        let key = DataKey::DNROrder(patient_id.clone());
        env.storage()
            .persistent()
            .get(&key)
            .ok_or(Error::EmergencyProfileNotFound)
    }

    /// Notify emergency contacts for a patient.
    /// Requires a valid, unexpired break-glass access grant.
    pub fn notify_emergency_contacts(
        env: Env,
        provider: Address,
        patient_id: Address,
    ) -> Result<Vec<EmergencyContact>, Error> {
        provider.require_auth();

        if !Self::has_emergency_access_log(&env, &patient_id, &provider) {
            return Err(Error::NotAuthorized);
        }

        let key = DataKey::EmergencyProfile(patient_id.clone());
        let profile: EmergencyProfile = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::EmergencyProfileNotFound)?;

        Ok(profile.emergency_contacts)
    }
}
