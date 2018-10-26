use neon::prelude::*;
use exception::*;
use buffer::*;
use wallet_wasm;

pub const SALT_SIZE  : usize = 32;
pub const NONCE_SIZE : usize = 12;
pub const TAG_SIZE   : usize = 16;

// Params: password: Buffer, salt: Buffer, nonce: Buffer, data: Buffer
pub fn encrypt_with_password(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let pwd = cx.argument::<JsBuffer>(0)?;
  let salt = cx.argument::<JsBuffer>(1)?;
  let nonce = cx.argument::<JsBuffer>(2)?;
  let data = cx.argument::<JsBuffer>(3)?;
  {
    let guard = cx.lock();

    let bsalt = salt.borrow(&guard);
    let bnonce = nonce.borrow(&guard);
    let bdata = data.borrow(&guard);

    if bsalt.len() == SALT_SIZE {
      if bnonce.len() == NONCE_SIZE {
        Ok(bdata.len() + TAG_SIZE + NONCE_SIZE + SALT_SIZE)
      } else {
        Err(format!("Wrong nonce len {} should be {}", bnonce.len(), NONCE_SIZE))
      }
    } else {
      Err(format!("Wrong salt len {} should be {}", bsalt.len(), SALT_SIZE))
    }
  }
  .or_throw(&mut cx)
  .and_then(|size| cx.buffer(size as u32))
  .and_then(|mut js_buffer| {
    {
      let guard = cx.lock();
      let bpwd: BufferPtr = pwd.borrow(&guard).into();
      let bsalt: BufferPtr = salt.borrow(&guard).into();
      let bnonce: BufferPtr = nonce.borrow(&guard).into();
      let bdata: BufferPtr = data.borrow(&guard).into();

      let output: MutBufferPtr = js_buffer.borrow_mut(&guard).into();

      handle_exception(|| {
        wallet_wasm::encrypt_with_password(
          bpwd.ptr, bpwd.size, bsalt.ptr, bnonce.ptr, bdata.ptr, bdata.size,
          output.ptr
        ) as usize
      }).and_then(|rsz| {
        if rsz != output.size {
          return Err(format!("Size mismatch {} should be {}", rsz, output.size));
        }
        Ok(js_buffer)
      })
    }.or_throw(&mut cx)
  })
}

// Params: password: Buffer, data: ArrayBuffer
pub fn decrypt_with_password(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let pwd = cx.argument::<JsBuffer>(0)?;
  let data = cx.argument::<JsBuffer>(1)?;
  {
    let guard = cx.lock();
    let bdata = data.borrow(&guard);

    if bdata.len() <= TAG_SIZE + NONCE_SIZE + SALT_SIZE { 
      Err(format!("Wrong data len {} should be at least {}", bdata.len(), TAG_SIZE + NONCE_SIZE + SALT_SIZE + 1))
    } else {
      Ok(bdata.len() - TAG_SIZE - NONCE_SIZE - SALT_SIZE)
    }
  }
  .or_throw(&mut cx)
  .and_then(|size| cx.buffer(size as u32))
  .and_then(|mut js_buffer| {
    {
      let guard = cx.lock();
      let bpwd: BufferPtr = pwd.borrow(&guard).into();
      let bdata: BufferPtr = data.borrow(&guard).into();

      let output: MutBufferPtr = js_buffer.borrow_mut(&guard).into();

      handle_exception(|| {
        wallet_wasm::decrypt_with_password(
          bpwd.ptr, bpwd.size, bdata.ptr, bdata.size,
          output.ptr
        ) as usize
      }).and_then(|rsz| {
        if rsz != output.size {
          return Err(format!("Size mismatch {} should be {}", rsz, output.size));
        }
        Ok(js_buffer)
      })
    }.or_throw(&mut cx)
  })
}
