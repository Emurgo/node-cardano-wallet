#[macro_use]
extern crate neon;

extern crate cardano;
extern crate wallet_wasm;

mod password_protect;
mod random_checker;
mod exception;
mod buffer;
mod hdwallet;
mod wallet;

pub const MAX_OUTPUT_SIZE: usize = 4096;

use neon::prelude::*;

fn init(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    exception::hide_exceptions();
    Ok(cx.undefined())
}

register_module!(mut cx, {
    cx.export_function("init_rust", init)?;
    cx.export_function("password_protect_encrypt_with_password", password_protect::encrypt_with_password)?;
    cx.export_function("password_protect_decrypt_with_password", password_protect::decrypt_with_password)?;
    cx.export_function("random_checker_new_checker", random_checker::new_checker)?;
    cx.export_function("random_checker_new_checker_from_mnemonics", random_checker::new_checker_from_mnemonics)?;
    cx.export_function("random_checker_check_addresses", random_checker::check_addresses)?;
    cx.export_function("hdwallet_from_enhanced_entropy", hdwallet::from_enhanced_entropy)?;
    cx.export_function("hdwallet_from_seed", hdwallet::from_seed)?;
    cx.export_function("hdwallet_to_public", hdwallet::to_public)?;
    cx.export_function("hdwallet_derive_private", hdwallet::derive_private)?;
    cx.export_function("hdwallet_derive_public", hdwallet::derive_public)?;
    cx.export_function("hdwallet_sign", hdwallet::sign)?;
    cx.export_function("wallet_from_master_key", wallet::from_master_key)?;
    cx.export_function("wallet_from_daedalus_mnemonic", wallet::from_daedalus_mnemonic)?;
    cx.export_function("wallet_new_account", wallet::new_account)?;
    cx.export_function("wallet_generate_addresses", wallet::generate_addresses)?;
    cx.export_function("wallet_check_address", wallet::check_address)?;
    cx.export_function("wallet_spend", wallet::spend)?;
    cx.export_function("wallet_move", wallet::move_func)
});
