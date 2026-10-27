//! Sample Soroban contract that routes authorization and TTL management
//! through local `macro_rules!` helpers inside a `#[contractimpl]` block.
//! The scanner should treat the macro invocations as the checks they expand
//! to, so the gated functions are clean and only `leak` is reported
//! (AP-AUTH-001): `npx tsx src/index.ts contracts/MacroExpandedVault.rs`

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

macro_rules! authorized {
    ($who:expr) => {
        $who.require_auth();
    };
}

macro_rules! keep_alive {
    ($env:expr, $key:expr) => {
        $env.storage().persistent().extend_ttl($key, 100, 200);
    };
}

#[contract]
pub struct MacroExpandedVault;

#[contractimpl]
impl MacroExpandedVault {
    /// Gated through the `authorized!` macro and bumped through `keep_alive!`.
    pub fn deposit(env: Env, owner: Address, amount: i128) {
        authorized!(owner);
        let key = DataKey::Balance(owner);
        env.storage().persistent().set(&key, &amount);
        keep_alive!(env, &key);
    }

    /// The macro is named in a comment only, so there is no real auth check.
    pub fn leak(env: Env, owner: Address, amount: i128) {
        // authorized!(owner);
        let key = DataKey::Balance(owner);
        env.storage().persistent().set(&key, &amount);
    }
}
