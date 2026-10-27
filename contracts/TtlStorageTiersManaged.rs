//! Managed counterpart of `TtlStorageTiers.rs`: persistent and temporary
//! entries are bumped with extend_ttl, writers call require_auth, and
//! expired reads return an error instead of unwrapping. The scanner should
//! report no findings.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env};

const LEDGER_THRESHOLD: u32 = 17_280;
const LEDGER_BUMP: u32 = 518_400;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Expired = 1,
}

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address),
}

#[contract]
pub struct TtlStorageTiersManaged;

#[contractimpl]
impl TtlStorageTiersManaged {
    pub fn set_balance(env: Env, owner: Address, amount: i128) {
        owner.require_auth();
        let key = DataKey::Balance(owner);
        env.storage().persistent().set(&key, &amount);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGER_THRESHOLD, LEDGER_BUMP);
    }

    pub fn balance(env: Env, owner: Address) -> Result<i128, Error> {
        let key = DataKey::Balance(owner);
        let value: Option<i128> = env.storage().persistent().get(&key);
        match value {
            Some(v) => {
                env.storage()
                    .persistent()
                    .extend_ttl(&key, LEDGER_THRESHOLD, LEDGER_BUMP);
                Ok(v)
            }
            None => Err(Error::Expired),
        }
    }

    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        let key = DataKey::Allowance(owner, spender);
        env.storage().temporary().set(&key, &amount);
        env.storage().temporary().extend_ttl(&key, 100, 200);
    }
}
