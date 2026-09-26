//! Tests for the dental records contract.

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String, Symbol, Vec};

fn setup() -> (Env, DentalRecordsContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(DentalRecordsContract, ());
    let client = DentalRecordsContractClient::new(&env, &contract_id);
    (env, client)
}

fn empty_procedures(env: &Env) -> Vec<PlannedProcedure> {
    Vec::new(env)
}

#[test]
fn test_create_dental_chart() {
    let (env, client) = setup();
    let patient = Address::generate(&env);
    let dentist = Address::generate(&env);

    let chart_id = client.create_dental_chart(
        &patient,
        &dentist,
        &1_700_000_000,
        &Symbol::new(&env, "fdi"),
    );

    assert_eq!(chart_id, 1);
}

#[test]
fn test_record_tooth_condition() {
    let (env, client) = setup();
    let patient = Address::generate(&env);
    let dentist = Address::generate(&env);

    let chart_id = client.create_dental_chart(
        &patient,
        &dentist,
        &1_700_000_000,
        &Symbol::new(&env, "fdi"),
    );

    client.record_tooth_condition(
        &chart_id,
        &String::from_str(&env, "11"),
        &Some(Symbol::new(&env, "occlusal")),
        &Symbol::new(&env, "caries"),
        &None,
    );
}

#[test]
fn test_record_periodontal_assessment() {
    let (env, client) = setup();
    let patient = Address::generate(&env);
    let dentist = Address::generate(&env);

    let chart_id = client.create_dental_chart(
        &patient,
        &dentist,
        &1_700_000_000,
        &Symbol::new(&env, "fdi"),
    );

    client.record_periodontal_assessment(
        &chart_id,
        &String::from_str(&env, "11"),
        &Symbol::new(&env, "mb"),
        &3,
        &0,
        &false,
        &None,
    );
}

#[test]
fn test_create_treatment_plan() {
    let (env, client) = setup();
    let patient = Address::generate(&env);
    let dentist = Address::generate(&env);

    let plan_id = client.create_treatment_plan(
        &patient,
        &dentist,
        &1_700_000_000,
        &empty_procedures(&env),
        &false,
        &1000,
    );

    assert_eq!(plan_id, 1);
}

#[test]
fn test_schedule_dental_procedure() {
    let (env, client) = setup();
    let patient = Address::generate(&env);
    let dentist = Address::generate(&env);

    let plan_id = client.create_treatment_plan(
        &patient,
        &dentist,
        &1_700_000_000,
        &empty_procedures(&env),
        &false,
        &1000,
    );

    let appt_id = client.schedule_dental_procedure(
        &plan_id,
        &1,
        &(env.ledger().timestamp() + 86_400),
        &30,
        &false,
    );

    assert_eq!(appt_id, 1);
}

#[test]
fn test_document_procedure_performed() {
    let (env, client) = setup();
    let patient = Address::generate(&env);
    let dentist = Address::generate(&env);

    let plan_id = client.create_treatment_plan(
        &patient,
        &dentist,
        &1_700_000_000,
        &empty_procedures(&env),
        &false,
        &1000,
    );

    let appt_id = client.schedule_dental_procedure(
        &plan_id,
        &1,
        &(env.ledger().timestamp() + 86_400),
        &30,
        &false,
    );

    client.document_procedure_performed(
        &appt_id,
        &dentist,
        &env.ledger().timestamp(),
        &Vec::new(&env),
        &Vec::new(&env),
        &None,
        &BytesN::from_array(&env, &[0u8; 32]),
    );
}

#[test]
fn test_document_procedure_performed_unauthorized_dentist() {
    let (env, client) = setup();
    let patient = Address::generate(&env);
    let dentist = Address::generate(&env);
    let other_dentist = Address::generate(&env);

    let plan_id = client.create_treatment_plan(
        &patient,
        &dentist,
        &1_700_000_000,
        &empty_procedures(&env),
        &false,
        &1000,
    );

    let appt_id = client.schedule_dental_procedure(
        &plan_id,
        &1,
        &(env.ledger().timestamp() + 86_400),
        &30,
        &false,
    );

    let result = client.try_document_procedure_performed(
        &appt_id,
        &other_dentist,
        &env.ledger().timestamp(),
        &Vec::new(&env),
        &Vec::new(&env),
        &None,
        &BytesN::from_array(&env, &[0u8; 32]),
    );

    assert_eq!(result, Err(Ok(Error::Unauthorized)));
}

#[test]
fn test_document_procedure_performed_missing_appointment() {
    let (env, client) = setup();
    let dentist = Address::generate(&env);

    let result = client.try_document_procedure_performed(
        &999,
        &dentist,
        &env.ledger().timestamp(),
        &Vec::new(&env),
        &Vec::new(&env),
        &None,
        &BytesN::from_array(&env, &[0u8; 32]),
    );

    assert_eq!(result, Err(Ok(Error::NotFound)));
}
