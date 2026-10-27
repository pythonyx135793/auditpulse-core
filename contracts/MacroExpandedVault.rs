//! Sample Soroban contract that routes authorization and TTL management
//! through local `macro_rules!` helpers inside a `#[contractimpl]` block.
//! AP-AUTH-001 treats calls to the local auth macro as auth checks, so only
//! `leak` is reported. AP-STORAGE-001 is a file-level text match for
//! `extend_ttl`; it does not expand macros or compare temporary vs persistent
//! kind, so `cross_kind` is not reported either. Expected output is a single
//! AP-AUTH-001 finding: `npx tsx src/index.ts contracts/MacroExpandedVault.rs`

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

macro_rules! keep_alive_tmp {
    ($env:expr, $key:expr) => {
        $env.storage().temporary().extend_ttl($key, 10, 20);
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

    /// Temporary entry bumped through the temporary-kind macro.
    pub fn stash(env: Env, owner: Address, amount: i128) {
        authorized!(owner);
        let key = DataKey::Balance(owner);
        env.storage().temporary().set(&key, &amount);
        keep_alive_tmp!(env, &key);
    }

    /// Cross-kind: writes temporary storage while only the persistent entry
    /// is bumped. AP-STORAGE-001 is file-level, so this is not reported.
    pub fn cross_kind(env: Env, owner: Address, amount: i128) {
        authorized!(owner);
        let key = DataKey::Balance(owner);
        env.storage().temporary().set(&key, &amount);
        env.storage().persistent().extend_ttl(&key, 100, 200);
    }

    /// The macro is named in a comment only, so there is no real auth check.
    pub fn leak(env: Env, owner: Address, amount: i128) {
        // authorized!(owner);
        let key = DataKey::Balance(owner);
        env.storage().persistent().set(&key, &amount);
    }
}
