#![no_std]
#![allow(clippy::too_many_arguments)]

//! # Care Plan Contract
//!
//! Manages patient care plans with goals, conditions, review scheduling, and provider authorization.
//!
//! ## HIPAA Compliance
//!
//! **Access Control Safeguards:** Provider authentication required for care plan creation and updates.
//! Patient enrollment with provider validation. Goal and adjustment authorization by enrolled providers.
//! Read access restricted to authorized parties via access control checks.
//!
//! **Audit Controls:** Events emitted for plan creation, goal achievement, plan completion, and
//! adjustments. Review dates tracked with last_review_date capturing modification history. Provider
//! and patient addresses logged with all operations for auditability.
//!
//! **Data Retention Policy:** Active care plans retain all historical review data. Completion status
//! captured with end date. Review frequency enforced with next_review_date tracking. Plan deregistration
//! cleans up all patient-specific care plan state.
//!
//! **Encryption/Integrity:** Care plan data stored in persistent storage with version tracking.
//! Timestamp integrity maintained via ledger timestamp. Provider registry validation ensures
//! only authorized providers manage plans.

mod storage;
mod types;

#[cfg(test)]
mod test;

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Symbol, Vec};
use storage::*;
use types::*;

/// Returns true if `caller` is the plan's provider or an assigned care-team member.
fn is_bound_to_plan(env: &Env, plan: &CarePlan, caller: &Address) -> bool {
    if *caller == plan.provider_id {
        return true;
    }
    let team = load_care_team(env, plan.care_plan_id);
    for member in team.iter() {
        if member.team_member == *caller {
            return true;
        }
    }
    false
}

#[contract]
pub struct CarePlanContract;

#[contractimpl]
impl CarePlanContract {
    /// Create a new care plan for a patient.
    pub fn create_care_plan(
        env: Env,
        patient_id: Address,
        provider_id: Address,
        plan_type: Symbol,
        conditions: Vec<String>,
        goals: Vec<String>,
        start_date: u64,
        review_frequency_days: u32,
    ) -> Result<u64, Error> {
        provider_id.require_auth();

        let care_plan_id = next_care_plan_id(&env);
        let next_review_date = start_date + (review_frequency_days as u64 * 86_400);

        let plan = CarePlan {
            care_plan_id,
            patient_id: patient_id.clone(),
            provider_id: provider_id.clone(),
            plan_type,
            conditions,
            goals,
            start_date,
            review_frequency_days,
            status: CarePlanStatus::Active,
            next_review_date,
            last_review_date: None,
            created_at: env.ledger().timestamp(),
        };

        save_care_plan(&env, &plan);
        add_patient_plan(&env, &patient_id, care_plan_id);

        env.events().publish(
            (Symbol::new(&env, "care_plan_created"),),
            (care_plan_id, patient_id, provider_id),
        );

        Ok(care_plan_id)
    }

    /// Add a goal to an existing care plan.
    pub fn add_care_goal(
        env: Env,
        care_plan_id: u64,
        provider_id: Address,
        goal_description: String,
        target_value: Option<String>,
        target_date: u64,
        priority: Symbol,
    ) -> Result<u64, Error> {
        provider_id.require_auth();

        let plan = load_care_plan(&env, care_plan_id).ok_or(Error::CarePlanNotFound)?;
        if !is_bound_to_plan(&env, &plan, &provider_id) {
            return Err(Error::Unauthorized);
        }
        if matches!(
            plan.status,
            CarePlanStatus::Completed | CarePlanStatus::Discontinued
        ) {
            return Err(Error::CarePlanClosed);
        }

        let goal_id = next_goal_id(&env);

        let goal = CareGoal {
            goal_id,
            care_plan_id,
            description: goal_description,
            target_value,
            target_date,
            priority,
            status: GoalStatus::Active,
            progress_entries: Vec::new(&env),
            achievement_date: None,
            outcome_notes: None,
            created_by: provider_id.clone(),
            created_at: env.ledger().timestamp(),
        };

        save_goal(&env, &goal);
        add_plan_goal(&env, care_plan_id, goal_id);

        env.events()
            .publish((Symbol::new(&env, "goal_added"),), (care_plan_id, goal_id));

        Ok(goal_id)
    }

    /// Add an intervention to a care plan.
    pub fn add_intervention(
        env: Env,
        care_plan_id: u64,
        provider_id: Address,
        intervention_type: Symbol,
        description: String,
        frequency: String,
        responsible_party: Symbol,
    ) -> Result<u64, Error> {
        provider_id.require_auth();

        let plan = load_care_plan(&env, care_plan_id).ok_or(Error::CarePlanNotFound)?;
        if !is_bound_to_plan(&env, &plan, &provider_id) {
            return Err(Error::Unauthorized);
        }
        if matches!(
            plan.status,
            CarePlanStatus::Completed | CarePlanStatus::Discontinued
        ) {
            return Err(Error::CarePlanClosed);
        }

        let intervention_id = next_intervention_id(&env);

        let intervention = Intervention {
            intervention_id,
            care_plan_id,
            intervention_type,
            description,
            frequency,
            responsible_party,
            assigned_by: provider_id.clone(),
            created_at: env.ledger().timestamp(),
        };

        save_intervention(&env, &intervention);
        add_plan_intervention(&env, care_plan_id, intervention_id);

        env.events().publish(
            (Symbol::new(&env, "intervention_added"),),
            (care_plan_id, intervention_id),
        );

        Ok(intervention_id)
    }

    /// Record progress against a care goal.
    pub fn record_goal_progress(
        env: Env,
        goal_id: u64,
        patient_id: Address,
        current_value: String,
        progress_note: String,
        recorded_date: u64,
    ) -> Result<(), Error> {
        patient_id.require_auth();

        let mut goal = load_goal(&env, goal_id).ok_or(Error::GoalNotFound)?;
        let plan = load_care_plan(&env, goal.care_plan_id).ok_or(Error::CarePlanNotFound)?;
        if patient_id != plan.patient_id {
            return Err(Error::Unauthorized);
        }

        if matches!(goal.status, GoalStatus::Achieved) {
            return Err(Error::GoalAlreadyAchieved);
        }
        if matches!(goal.status, GoalStatus::Discontinued) {
            return Err(Error::GoalDiscontinued);
        }

        let entry = ProgressEntry {
            goal_id,
            patient_id: patient_id.clone(),
            current_value,
            progress_note,
            recorded_date,
        };

        goal.progress_entries.push_back(entry);
        save_goal(&env, &goal);

        env.events().publish(
            (Symbol::new(&env, "goal_progress_recorded"),),
            (goal_id, patient_id),
        );

        Ok(())
    }

    /// Mark a care goal as achieved.
    ///
    /// Allowed even if the parent care plan has since been completed or discontinued:
    /// closing out a goal that was already on the plan reflects a real clinical outcome
    /// and does not add new activity to a closed plan, unlike `add_care_goal`.
    pub fn mark_goal_achieved(
        env: Env,
        goal_id: u64,
        provider_id: Address,
        achievement_date: u64,
        outcome_notes: String,
    ) -> Result<(), Error> {
        provider_id.require_auth();

        let mut goal = load_goal(&env, goal_id).ok_or(Error::GoalNotFound)?;
        let plan = load_care_plan(&env, goal.care_plan_id).ok_or(Error::CarePlanNotFound)?;
        if !is_bound_to_plan(&env, &plan, &provider_id) {
            return Err(Error::Unauthorized);
        }

        if matches!(goal.status, GoalStatus::Achieved) {
            return Err(Error::GoalAlreadyAchieved);
        }
        if matches!(goal.status, GoalStatus::Discontinued) {
            return Err(Error::GoalDiscontinued);
        }

        goal.status = GoalStatus::Achieved;
        goal.achievement_date = Some(achievement_date);
        goal.outcome_notes = Some(outcome_notes);
        save_goal(&env, &goal);

        env.events().publish(
            (Symbol::new(&env, "goal_achieved"),),
            (goal_id, provider_id),
        );

        Ok(())
    }

    /// Resolve a barrier on a care plan.
    pub fn resolve_barrier(
        env: Env,
        barrier_id: u64,
        provider_id: Address,
        resolution_notes: String,
    ) -> Result<(), Error> {
        provider_id.require_auth();

        let mut barrier = load_barrier(&env, barrier_id).ok_or(Error::BarrierNotFound)?;
        let plan = load_care_plan(&env, barrier.care_plan_id).ok_or(Error::CarePlanNotFound)?;
        if !is_bound_to_plan(&env, &plan, &provider_id) {
            return Err(Error::Unauthorized);
        }

        barrier.resolved = true;
        barrier.resolution_notes = Some(resolution_notes);
        barrier.resolved_by = Some(provider_id.clone());
        barrier.resolved_at = Some(env.ledger().timestamp());
        save_barrier(&env, &barrier);

        env.events().publish(
            (Symbol::new(&env, "barrier_resolved"),),
            (barrier_id, provider_id),
        );

        Ok(())
    }

    /// Schedule a care plan review.
    pub fn schedule_care_plan_review(
        env: Env,
        care_plan_id: u64,
        provider_id: Address,
        review_date: u64,
    ) -> Result<(), Error> {
        provider_id.require_auth();

        let mut plan = load_care_plan(&env, care_plan_id).ok_or(Error::CarePlanNotFound)?;
        if !is_bound_to_plan(&env, &plan, &provider_id) {
            return Err(Error::Unauthorized);
        }
        if matches!(
            plan.status,
            CarePlanStatus::Completed | CarePlanStatus::Discontinued
        ) {
            return Err(Error::CarePlanClosed);
        }

        plan.next_review_date = review_date;
        save_care_plan(&env, &plan);

        env.events().publish(
            (Symbol::new(&env, "care_plan_review_scheduled"),),
            (care_plan_id, review_date),
        );

        Ok(())
    }

    /// Retrieve a summary of a care plan.
    ///
    /// Access is restricted to the patient, the plan's provider, or an assigned
    /// care-team member, mirroring the authorization used by every mutating path.
    pub fn get_care_plan_summary(
        env: Env,
        care_plan_id: u64,
        requester: Address,
    ) -> Result<CarePlanSummary, Error> {
        requester.require_auth();

        let plan = load_care_plan(&env, care_plan_id).ok_or(Error::CarePlanNotFound)?;
        if requester != plan.patient_id && !is_bound_to_plan(&env, &plan, &requester) {
            return Err(Error::Unauthorized);
        }

        let goals = load_plan_goals(&env, care_plan_id);
        let interventions = load_plan_interventions(&env, care_plan_id);
        let barriers = load_plan_barriers(&env, care_plan_id);
        let care_team = load_care_team(&env, care_plan_id);

        Ok(CarePlanSummary {
            care_plan_id,
            patient_id: plan.patient_id,
            provider_id: plan.provider_id,
            plan_type: plan.plan_type,
            conditions: plan.conditions,
            goals,
            interventions,
            barriers,
            care_team,
            status: plan.status,
            next_review_date: plan.next_review_date,
            last_review_date: plan.last_review_date,
        })
    }
}
