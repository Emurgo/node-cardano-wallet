use neon::prelude::*;
use exception::*;
use buffer::*;
use wallet_wasm;
use std::str;
use super::MAX_OUTPUT_SIZE;

// Params: xprv: "HexString"
pub fn new_checker(mut cx: FunctionContext) -> JsResult<JsString> {
  let xprv_str = cx.argument::<JsString>(0)?.value();
  let mut output = [0 as u8; MAX_OUTPUT_SIZE];
  let buf = MutBufferPtr::from(&mut output);
  
  handle_exception(|| {
    let xprv: &[u8] = xprv_str.as_bytes();
    
    let rsz = wallet_wasm::random_address_checker_new(xprv.as_ptr(), xprv.len(), buf.ptr);

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > MAX_OUTPUT_SIZE { panic!("Response {} >= {}", rsz, MAX_OUTPUT_SIZE) }

    buf.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}

// Params: mnemonics: "String"
pub fn new_checker_from_mnemonics(mut cx: FunctionContext) -> JsResult<JsString> {
  let mnemonics_str = cx.argument::<JsString>(0)?.value();
  let mut output = [0 as u8; MAX_OUTPUT_SIZE];
  let buf = MutBufferPtr::from(&mut output);
  
  handle_exception(|| {
    let mnemonics: &[u8] = mnemonics_str.as_bytes();
    
    let rsz = wallet_wasm::random_address_checker_from_mnemonics(mnemonics.as_ptr(), mnemonics.len(), buf.ptr);

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > MAX_OUTPUT_SIZE { panic!("Response {} >= {}", rsz, MAX_OUTPUT_SIZE) }

    buf.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}

// Params: params: JSONString, alen: Number
pub fn check_addresses(mut cx: FunctionContext) -> JsResult<JsString> {
  let params_str = cx.argument::<JsString>(0)?.value();
  let alen = cx.argument::<JsNumber>(1)?.value() as u32 as usize;
  
  let output_size = (alen as usize) * 4096;
  let mut output: Vec<u8> = Vec::new();
  output.resize(output_size, 0);

  let buf = MutBufferPtr::from(&mut output);
  
  handle_exception(|| {
    let params: &[u8] = params_str.as_bytes();
    
    let rsz = wallet_wasm::random_address_check(params.as_ptr(), params.len(), buf.ptr);

    if rsz <= 0 { panic!("Response {} <= 0", rsz); }
    if (rsz as usize) > output_size { panic!("Response {} >= {}", rsz, output_size) }

    buf.as_sized_slice(rsz as usize)
  }).map(|output| {
    unsafe { str::from_utf8_unchecked(output) }
  })
  .and_then(|string| {
    cx.try_string(string).map_err(|_| String::from("Can't create JS string"))
  }).or_throw(&mut cx)
}