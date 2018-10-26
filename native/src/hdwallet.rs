use neon::prelude::*;
use exception::*;
use buffer::*;
use wallet_wasm;
use cardano::hdwallet;

// Params: entropy: Buffer, password: String
pub fn from_enhanced_entropy(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let entropy = cx.argument::<JsBuffer>(0)?;
  let pwd_str = cx.argument::<JsString>(1)?.value();

  let mut output_buf = cx.buffer(hdwallet::XPRV_SIZE as u32)?;
  {
    let guard = cx.lock();
    let entropy_buf: BufferPtr = entropy.borrow(&guard).into();
    let output: MutBufferPtr = output_buf.borrow_mut(&guard).into();

    handle_exception(|| {
      let pwd: &[u8] = pwd_str.as_bytes();
      let res = wallet_wasm::wallet_from_enhanced_entropy(
        entropy_buf.ptr, entropy_buf.size, pwd.as_ptr(), pwd.len(), output.ptr
      );

      if res != 0 { panic!("Rust method error. Check entropy size.") }
    }).map(|_| output_buf )
  }.or_throw(&mut cx)
}

// Params: seed: Buffer
pub fn from_seed(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let seed = cx.argument::<JsBuffer>(0)?;
  let mut output_buf = cx.buffer(hdwallet::XPRV_SIZE as u32)?;

  {
    let guard = cx.lock();
    let seed_buf: BufferPtr = seed.borrow(&guard).into();
    let output: MutBufferPtr = output_buf.borrow_mut(&guard).into();

    handle_exception(|| {
      if seed_buf.size != hdwallet::SEED_SIZE { 
        panic!("Wrong seed len {} should be {}", seed_buf.size, hdwallet::SEED_SIZE);
      }
      wallet_wasm::wallet_from_seed(seed_buf.ptr, output.ptr);
    }).map(|_| output_buf )
  }.or_throw(&mut cx)
}

// Params: xprv: Buffer
pub fn to_public(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let xprv = cx.argument::<JsBuffer>(0)?;
  let mut output_buf = cx.buffer(hdwallet::XPUB_SIZE as u32)?;

  {
    let guard = cx.lock();
    let xprv_buf: BufferPtr = xprv.borrow(&guard).into();
    let output: MutBufferPtr = output_buf.borrow_mut(&guard).into();

    handle_exception(|| {
      if xprv_buf.size != hdwallet::XPRV_SIZE { 
        panic!("Wrong XPrv len {} should be {}", xprv_buf.size, hdwallet::XPRV_SIZE);
      }
      wallet_wasm::wallet_to_public(xprv_buf.ptr, output.ptr);
    }).map(|_| output_buf )
  }.or_throw(&mut cx)
}

// Params: xprv: Buffer, index: Number
pub fn derive_private(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let xprv = cx.argument::<JsBuffer>(0)?;
  let index = cx.argument::<JsNumber>(1)?.value() as u32;
  let mut output_buf = cx.buffer(hdwallet::XPRV_SIZE as u32)?;

  {
    let guard = cx.lock();
    let xprv_buf: BufferPtr = xprv.borrow(&guard).into();
    let output: MutBufferPtr = output_buf.borrow_mut(&guard).into();

    handle_exception(|| {
      if xprv_buf.size != hdwallet::XPRV_SIZE { 
        panic!("Wrong XPrv len {} should be {}", xprv_buf.size, hdwallet::XPRV_SIZE);
      }
      wallet_wasm::wallet_derive_private(xprv_buf.ptr, index, output.ptr);
    }).map(|_| output_buf )
  }.or_throw(&mut cx)
}

// Params: xpub: Buffer, index: Number
pub fn derive_public(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let xpub = cx.argument::<JsBuffer>(0)?;
  let index = cx.argument::<JsNumber>(1)?.value() as u32;
  let mut output_buf = cx.buffer(hdwallet::XPUB_SIZE as u32)?;

  {
    let guard = cx.lock();
    let xpub_buf: BufferPtr = xpub.borrow(&guard).into();
    let output: MutBufferPtr = output_buf.borrow_mut(&guard).into();

    handle_exception(|| {
      if xpub_buf.size != hdwallet::XPUB_SIZE { 
        panic!("Wrong XPub len {} should be {}", xpub_buf.size, hdwallet::XPUB_SIZE);
      }
      if index >= 0x80000000 {
        panic!("Cannot do public derivation with hard index");
      }
      let res = wallet_wasm::wallet_derive_public(xpub_buf.ptr, index, output.ptr);

      if !res { panic!("Can't derive public key"); }
    }).map(|_| output_buf )
  }.or_throw(&mut cx)
}

// Params: xprv: Buffer, data: Buffer
pub fn sign(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let xprv = cx.argument::<JsBuffer>(0)?;
  let data = cx.argument::<JsBuffer>(1)?;
  let mut output_buf = cx.buffer(hdwallet::SIGNATURE_SIZE as u32)?;

  {
    let guard = cx.lock();
    let xprv_buf: BufferPtr = xprv.borrow(&guard).into();
    let data_buf: BufferPtr = data.borrow(&guard).into();
    let output: MutBufferPtr = output_buf.borrow_mut(&guard).into();

    handle_exception(|| {
      if xprv_buf.size != hdwallet::XPRV_SIZE { 
        panic!("Wrong XPrv len {} should be {}", xprv_buf.size, hdwallet::XPRV_SIZE);
      }
      wallet_wasm::wallet_sign(xprv_buf.ptr, data_buf.ptr, data_buf.size, output.ptr);
    }).map(|_| output_buf )
  }.or_throw(&mut cx)
}