import * as rncardano from './rncardano';

export namespace HdWallet {
  export type XPrv = Buffer;
  export type XPub = Buffer;
  
  // Generate an eXtended private key from the given entropy and the given password.
  export function fromEnhancedEntropy(entropy: Buffer, password: Buffer): XPrv;
  
  // Create a private key from the given seed.
  export function fromSeed(seed: Buffer): XPrv;
  
  // Get a public key for the private one.
  export function toPublic(xprv: XPrv): XPub;
  
  // Create a derived private key with an index.
  export function derivePrivate(xprv: XPrv, index: number): XPrv;
  
  // Create a derived public key with an index.
  export function derivePublic(xpub: XPub, index: number): XPub;
  
  // Sign the given message with the private key.
  export function sign(xprv: XPrv, msg: Buffer): Buffer;
}
  
export namespace Wallet {
  export type TransactionObj = {
    cbor_encoded_tx: Buffer;
    change_used: boolean;
    fee: string;
  };
  
  // Create a wallet object from the given seed.
  export function fromMasterKey(xprv: HdWallet.XPrv): rncardano.Wallet.WalletObj;
  
  // Create a daedalus wallet object from the given seed.
  export function fromDaedalusMnemonic(mnemonics: string): rncardano.Wallet.DaedalusWalletObj;
  
  // Create an account, for public key derivation (using bip44 model).
  export function newAccount(wallet: rncardano.Wallet.WalletObj, account: number): rncardano.Wallet.AccountObj;
  
  // Generate addresses for the given wallet.
  export function generateAddresses(
    account: rncardano.Wallet.AccountObj, type: rncardano.Wallet.AddressType, indices: Array<number>
  ): Array<rncardano.Wallet.Address>;

  // Check if the given Buffer is a valid Cardano Extended Address.
  export function checkAddress(address: Buffer): boolean;
  
  // Generate a ready to send, signed, transaction.
  export function spend(
    wallet: rncardano.Wallet.WalletObj, inputs: Array<rncardano.Wallet.SpendInputObj>,
    outputs: Array<rncardano.Wallet.OutputObj>, change_addr: rncardano.Wallet.Address
  ): TransactionObj;
  
  // Move all UTxO to a single address.
  export function move(
    wallet: rncardano.Wallet.DaedalusWalletObj,
    inputs: Array<rncardano.Wallet.MoveInputObj>,
    output: rncardano.Wallet.Address
  ): TransactionObj;
}
  
export namespace RandomAddressChecker {  
  // Create a random address checker, this will allow validating.
  export function newChecker(xprv: HdWallet.XPrv): rncardano.RandomAddressChecker.AddressCheckerObj;
  
  // Create a random address checker from daedalus mnemonics.
  export function newCheckerFromMnemonics(mnemonics: string): rncardano.RandomAddressChecker.AddressCheckerObj;
  
  // Check if the given addresses are valid.
  export function checkAddresses(
    checker: rncardano.RandomAddressChecker.AddressCheckerObj, addresses: Array<rncardano.Wallet.Address>
  ): Array<{ address: rncardano.Wallet.Address, addressing: [number, number] }>;
}
  
export namespace PasswordProtect {
  // Encrypt the given data with the password, salt and nonce.
  export function encryptWithPassword(
    password: Buffer, salt: Buffer, nonce: Buffer, data: Buffer
  ): Buffer;
  
  // Decrypt the given data with the password.
  export function decryptWithPassword(password: Buffer, data: Buffer): Buffer;
}

export { rncardano };