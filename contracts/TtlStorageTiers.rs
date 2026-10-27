//! Sample Soroban contract: temporary vs. persistent storage TTL edge cases.
//!
//! Every entry here is written or read without ever being bumped, so it can
//! expire silently. The scanner is expected to flag it (AP-STORAGE-001,
//! AP-ERROR-001): `npx tsx src/index.ts contracts/TtlStorageTiers.rs`
//! The managed counterpart is `contracts/TtlStorageTiersManaged.rs`.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address),
    Nonce(Address),
}

#[contract]
pub struct TtlStorageTiers;

#[contractimpl]
impl TtlStorageTiers {
    /// Persistent entry written once and never extended: expires after its
    /// default TTL and then reads back as missing.
    pub fn set_balance(env: Env, owner: Address, amount: i128) {
        owner.require_auth();
        env.storage().persistent().set(&DataKey::Balance(owner), &amount);
    }

    /// Edge case: reading an entry that may already have expired and
    /// unwrapping it traps the whole invocation.
    pub fn balance(env: Env, owner: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(owner))
            .unwrap()
    }

    /// Temporary entries are meant to expire, but a short-lived allowance
    /// that is expected to survive several ledgers still needs a bump.
    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        env.storage()
            .temporary()
            .set(&DataKey::Allowance(owner, spender), &amount);
    }

    /// Instance storage shares one TTL for the whole contract; it is never
    /// extended here either.
    pub fn bump_nonce(env: Env, owner: Address) -> u32 {
        owner.require_auth();
        let key = DataKey::Nonce(owner);
        let next: u32 = env.storage().instance().get(&key).unwrap_or(0) + 1;
        env.storage().instance().set(&key, &next);
        next
    }

    /// The only TTL mention is commented out, so it must not count as management.
    pub fn touch(env: Env, owner: Address) {
        owner.require_auth();
        let key = DataKey::Balance(owner);
        // env.storage().persistent().extend_ttl(&key, 100, 200);
        let _ = env.storage().persistent().has(&key);
        let _ = Symbol::new(&env, "touched");
    }
}
