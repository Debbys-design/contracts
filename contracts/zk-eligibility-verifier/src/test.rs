#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;

fn setup() -> (Env, ZkEligibilityVerifierClient<'static>) {
    let env = Env::default();
    let contract_id = env.register(ZkEligibilityVerifier, ());
    let client = ZkEligibilityVerifierClient::new(&env, &contract_id);
    (env, client)
}

#[test]
fn test_initialize() {
    let (env, client) = setup();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let zk_contract = Address::generate(&env);

    client.initialize(&admin, &zk_contract);
}

#[test]
#[should_panic]
fn test_unauthorized_caller_rejected() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let zk_contract = Address::generate(&env);

    // No auths mocked: admin.require_auth() must reject this call.
    client.initialize(&admin, &zk_contract);
}

#[test]
fn test_double_initialize_rejected() {
    let (env, client) = setup();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let zk_contract = Address::generate(&env);

    client.initialize(&admin, &zk_contract);
    let result = client.try_initialize(&admin, &zk_contract);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_check_eligibility_uninitialized_returns_false() {
    let (env, client) = setup();
    let user = Address::generate(&env);

    // No initialize call: the "not initialized -> false" fallback must apply.
    assert!(!client.check_eligibility(&user));
}

#[test]
fn test_check_eligibility_delegates_to_zk_contract() {
    let (env, client) = setup();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let zk_contract = Address::generate(&env);
    let user = Address::generate(&env);

    client.initialize(&admin, &zk_contract);

    // The configured zk_eligibility_contract is not registered in this env, so
    // the cross-contract delegation cannot succeed and the verifier must fall
    // back to false rather than panicking.
    assert!(!client.check_eligibility(&user));
}

#[test]
fn test_set_zk_eligibility_contract_admin_success() {
    let (env, client) = setup();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let zk_contract = Address::generate(&env);
    let new_zk_contract = Address::generate(&env);

    client.initialize(&admin, &zk_contract);
    client.set_zk_eligibility_contract(&admin, &new_zk_contract);
}

#[test]
fn test_set_zk_eligibility_contract_non_admin_rejected() {
    let (env, client) = setup();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let zk_contract = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let new_zk_contract = Address::generate(&env);

    client.initialize(&admin, &zk_contract);
    let result = client.try_set_zk_eligibility_contract(&non_admin, &new_zk_contract);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
}

#[test]
fn test_set_zk_eligibility_contract_uninitialized_rejected() {
    let (env, client) = setup();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_zk_contract = Address::generate(&env);

    let result = client.try_set_zk_eligibility_contract(&admin, &new_zk_contract);
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}
