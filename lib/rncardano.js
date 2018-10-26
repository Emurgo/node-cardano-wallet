const main = require("./index");

var PasswordProtect = {
  encryptWithPassword: function (password, salt, nonce, data) {
    return Promise.resolve().then(function () {
      return main.PasswordProtect.encryptWithPassword(
        password, Buffer.from(salt, 'hex'), Buffer.from(nonce, 'hex'), Buffer.from(data, 'hex')
      ).toString('hex');
    });
  },
  decryptWithPassword: function (password, data) {
    return Promise.resolve().then(function () {
      return main.PasswordProtect.decryptWithPassword(password, Buffer.from(data, 'hex').toString('hex'));
    });
  }
};

var RandomAddressChecker = {
  newChecker: function (xprv) {
    return Promise.resolve().then(function() {
      return main.RandomAddressChecker.newChecker(Buffer.from(xprv, 'hex'));
    });
  },
  newCheckerFromMnemonics: function (mnemonics) {
    return Promise.resolve().then(function() {
      return main.RandomAddressChecker.newCheckerFromMnemonics(mnemonics);
    });
  },
  checkAddresses: function (checker, addresses) {
    return Promise.resolve().then(function() {
      return main.RandomAddressChecker.checkAddresses(checker, addresses);
    });
  }
};

var HdWallet = {
  fromEnhancedEntropy: function (entropy, password) {
    return Promise.resolve().then(function() {
      return main.HdWallet.fromEnhancedEntropy(Buffer.from(entropy, 'hex'), password).toString('hex');
    });
  },
  fromSeed: function (seed) {
    return Promise.resolve().then(function() {
      return main.HdWallet.fromSeed(Buffer.from(seed, 'hex')).toString('hex');
    });
  },
  toPublic: function (xprv) {
    return Promise.resolve().then(function() {
      return main.HdWallet.toPublic(Buffer.from(xprv, 'hex')).toString('hex');
    });
  },
  derivePrivate: function (xprv, index) {
    return Promise.resolve().then(function() {
      return main.HdWallet.derivePrivate(Buffer.from(xprv, 'hex'), index).toString('hex');
    });
  },
  derivePublic: function (xpub, index) {
    return Promise.resolve().then(function() {
      return main.HdWallet.derivePublic(Buffer.from(xpub, 'hex'), index).toString('hex');
    });
  },
  sign: function (xprv, data) {
    return Promise.resolve().then(function() {
      return main.HdWallet.sign(Buffer.from(xprv, 'hex'), Buffer.from(data, 'hex')).toString('hex');
    });
  }
};

var Wallet = {
  fromMasterKey: function (xprv) {
    return Promise.resolve().then(function() {
      return main.Wallet.fromMasterKey(Buffer.from(xprv, 'hex'));
    });
  },
  fromDaedalusMnemonic: function (mnemonics) {
    return Promise.resolve().then(function() {
      return main.Wallet.fromDaedalusMnemonic(mnemonics);
    });
  },
  newAccount: function (wallet, account) {
    return Promise.resolve().then(function() {
      return main.Wallet.newAccount(wallet, account);
    });
  },
  generateAddresses: function (account, type, indices) {
    return Promise.resolve().then(function() {
      return main.Wallet.generateAddresses(account, type, indices);
    });
  },
  checkAddress: function (address) {
    return Promise.resolve().then(function() {
      return main.Wallet.checkAddress(Buffer.from(address, 'hex'));
    });
  },
  spend: function (wallet, inputs, outputs, change_addr) {
    return Promise.resolve().then(function() {
      var response = main.Wallet.spend(wallet, inputs, outputs, change_addr);
      response['cbor_encoded_tx'] = response['cbor_encoded_tx'].toString('hex');
      return response;
    });
  },
  move: function (wallet, inputs, output) {
    return Promise.resolve().then(function() {
      var response = main.Wallet.move(wallet, inputs, output);
      response['cbor_encoded_tx'] = response['cbor_encoded_tx'].toString('hex');
      return response;
    });
  }
};

exports.PasswordProtect = Object.freeze(PasswordProtect);
exports.RandomAddressChecker = Object.freeze(RandomAddressChecker);
exports.HdWallet = Object.freeze(HdWallet);
exports.Wallet = Object.freeze(Wallet);