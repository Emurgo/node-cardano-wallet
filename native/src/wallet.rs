use neon::prelude::*;
use exception::*;
use buffer::*;
use wallet_wasm;
use std::str;
use cardano::util::{base58, hex};
use super::MAX_OUTPUT_SIZE;

// Params: xprv: Buffer
pub fn from_master_key(mut cx: FunctionContext) -> JsResult<JsString> {
  let xprv = cx.argument::<JsBuffer>(0)?;

  let mut output_data = [0 as u8; MAX_OUTPUT_SIZE];
  let output = MutBufferPtr::from(&mut output_data);
  {
    let guard = cx.lock();
    let xprv_buf: BufferPtr = xprv.borrow(&guard).into();

    handle_exception(|| {
      let rsz = wallet_wasm::xwallet_from_master_key(xprv_buf.ptr, output.ptr);
      if rsz <= 0 { panic!("Response {} <= 0", rsz); }
      if (rsz as usize) > MAX_OUTPUT_SIZE { panic!("Response {} >= {}", rsz, MAX_OUTPUT_SIZE) }
      output.as_sized_slice(rsz as usize)
    })
  }.map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}

// Params: mnemonic: "String"
pub fn from_daedalus_mnemonic(mut cx: FunctionContext) -> JsResult<JsString> {
  let mnemonic = cx.argument::<JsString>(0)?.value();
  
  let mut output_data = [0 as u8; MAX_OUTPUT_SIZE];
  let output = MutBufferPtr::from(&mut output_data);
  
  handle_exception(|| {
    let mnemonic_ptr: &[u8] = mnemonic.as_bytes();
    
    let rsz = wallet_wasm::xwallet_create_daedalus_mnemonic(
      mnemonic_ptr.as_ptr(), mnemonic_ptr.len(), output.ptr
    );

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > MAX_OUTPUT_SIZE { panic!("Response {} >= {}", rsz, MAX_OUTPUT_SIZE) }

    output.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}

// Params: params: JSONString
pub fn new_account(mut cx: FunctionContext) -> JsResult<JsString> {
  let params = cx.argument::<JsString>(0)?.value();
  
  let mut output_data = [0 as u8; MAX_OUTPUT_SIZE];
  let output = MutBufferPtr::from(&mut output_data);
  
  handle_exception(|| {
    let params_ptr: &[u8] = params.as_bytes();
    
    let rsz = wallet_wasm::xwallet_account(
      params_ptr.as_ptr(), params_ptr.len(), output.ptr
    );

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > MAX_OUTPUT_SIZE { panic!("Response {} >= {}", rsz, MAX_OUTPUT_SIZE) }

    output.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}

// Params: params: JSONString, alen: Number
pub fn generate_addresses(mut cx: FunctionContext) -> JsResult<JsString> {
  let params = cx.argument::<JsString>(0)?.value();
  let alen = cx.argument::<JsNumber>(1)?.value() as u32 as usize;
  
  let output_size = 131 * alen + 2; // (128 + 3 for meta) per addr + 2;
  let mut output_data: Vec<u8> = Vec::new();
  output_data.resize(output_size, 0);

  let output = MutBufferPtr::from(&mut output_data);
  
  handle_exception(|| {
    let params_ptr: &[u8] = params.as_bytes();
    
    let rsz = wallet_wasm::xwallet_addresses(
      params_ptr.as_ptr(), params_ptr.len(), output.ptr
    );

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > output_size { panic!("Response {} >= {}", rsz, output_size) }

    output.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}

// Params: address: String
pub fn check_address(mut cx: FunctionContext) -> JsResult<JsString> {
  let address = cx.argument::<JsString>(0)?.value();
  
  let mut output_data = [0 as u8; MAX_OUTPUT_SIZE];
  let output = MutBufferPtr::from(&mut output_data);
  
  handle_exception(|| {
    let decoded = base58::decode(&address).expect("Couldn't decode base58");
    let fixed_address = format!("\"{}\"", hex::encode(&decoded));
    let address_ptr: &[u8] = fixed_address.as_bytes();
    
    let rsz = wallet_wasm::xwallet_checkaddress(
      address_ptr.as_ptr(), address_ptr.len(), output.ptr
    );

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > MAX_OUTPUT_SIZE { panic!("Response {} >= {}", rsz, MAX_OUTPUT_SIZE) }

    output.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}

// Params: params: JSONString, ilen: Number, olen: Number
pub fn spend(mut cx: FunctionContext) -> JsResult<JsString> {
  let params = cx.argument::<JsString>(0)?.value();
  let ilen = cx.argument::<JsNumber>(1)?.value() as u32 as usize;
  let olen = cx.argument::<JsNumber>(2)?.value() as u32 as usize;
  
  let output_size = (ilen + olen + 1) * 65536 + 1024;
  let mut output_data: Vec<u8> = Vec::new();
  output_data.resize(output_size, 0);

  let output = MutBufferPtr::from(&mut output_data);
  
  handle_exception(|| {
    let params_ptr: &[u8] = params.as_bytes();
    
    let rsz = wallet_wasm::xwallet_spend(
      params_ptr.as_ptr(), params_ptr.len(), output.ptr
    );

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > output_size { panic!("Response {} >= {}", rsz, output_size) }

    output.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}

// Params: params: JSONString, ilen: Number
pub fn move_func(mut cx: FunctionContext) -> JsResult<JsString> {
  let params = cx.argument::<JsString>(0)?.value();
  let ilen = cx.argument::<JsNumber>(1)?.value() as u32 as usize;
  
  let output_size = (ilen + 1) * 65536 + 1024;
  let mut output_data: Vec<u8> = Vec::new();
  output_data.resize(output_size, 0);

  let output = MutBufferPtr::from(&mut output_data);
  
  handle_exception(|| {
    let params_ptr: &[u8] = params.as_bytes();
    
    let rsz = wallet_wasm::xwallet_move(
      params_ptr.as_ptr(), params_ptr.len(), output.ptr
    );

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > output_size { panic!("Response {} >= {}", rsz, output_size) }

    output.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}


