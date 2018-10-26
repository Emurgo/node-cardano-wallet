var rust = require('../native');
var bs58 = require('bs58');

rust.init_rust();

function handleResultString(value) {
  var data = JSON.parse(value);
  if (data.failed) {
    throw new Error("Error in: " + data.loc + ", message: " + data.msg);
  }
  return data.result;
}

var PasswordProtect = {
  encryptWithPassword: rust.password_protect_encrypt_with_password,
  decryptWithPassword: rust.password_protect_decrypt_with_password
};

var RandomAddressChecker = {
  newChecker: function (xprv) {
    return handleResultString(
      rust.random_checker_new_checker(JSON.stringify(xprv))
    );
  },
  newCheckerFromMnemonics: function (mnemonics) {
    return handleResultString(
      rust.random_checker_new_checker_from_mnemonics(JSON.stringify(mnemonics))
    );
  },
  checkAddresses: function (checker, addresses) {
    return handleResultString(
      rust.random_checker_check_addresses(
        JSON.stringify({checker: checker, addresses: addresses}),
        addresses.length
      )
    );
  }
};

var HdWallet = {
  fromEnhancedEntropy: rust.hdwallet_from_enhanced_entropy,
  fromSeed: rust.hdwallet_from_seed,
  toPublic: rust.hdwallet_to_public,
  derivePrivate: rust.hdwallet_derive_private,
  derivePublic: rust.hdwallet_derive_public,
  sign: rust.hdwallet_sign
};

var Wallet = {
  fromMasterKey: function (xprv) {
    return handleResultString(rust.wallet_from_master_key(xprv))
  },
  fromDaedalusMnemonic: function (mnemonics) {
    return handleResultString(
      rust.wallet_from_daedalus_mnemonic(JSON.stringify(mnemonics))
    );
  },
  newAccount: function (wallet, account) {
    return handleResultString(
      rust.wallet_new_account(JSON.stringify({ wallet: wallet, account: account }))
    )
  },
  generateAddresses: function (account, type, indices) {
    return handleResultString(
      rust.wallet_generate_addresses(
        JSON.stringify({ account: account, address_type: type, indices: indices }),
        indices.length
      )
    )
  },
  checkAddress: function (address) { // base58
    return handleResultString(
      rust.wallet_check_address(JSON.stringify(bs58.decode(address).toString('hex')))
    )
  },
  spend: function (wallet, inputs, outputs, change_addr) {
    var input = {
      wallet: wallet, inputs: inputs, 
      outputs: outputs, change_addr: change_addr
    };
    var response = handleResultString(
      rust.wallet_spend(JSON.stringify(input), inputs.length, outputs.length)
    );
    response['cbor_encoded_tx'] = Buffer.from(response['cbor_encoded_tx']);
    return response;
  },
  move: function (wallet, inputs, output) {
    var response =  handleResultString(
      rust.wallet_move(
        JSON.stringify({ wallet: wallet, inputs: inputs, output: output }),
        inputs.length
      )
    );
    response['cbor_encoded_tx'] = Buffer.from(response['cbor_encoded_tx']);
    return response;
  }
};

exports.PasswordProtect = Object.freeze(PasswordProtect);
exports.RandomAddressChecker = Object.freeze(RandomAddressChecker);
exports.HdWallet = Object.freeze(HdWallet);
exports.Wallet = Object.freeze(Wallet);