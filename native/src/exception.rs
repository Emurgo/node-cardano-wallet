use std::panic;
use std::result;
use neon::prelude::*;

pub type Result<T> = result::Result<T, String>;

pub trait NeonResultConvertible<T> {
    fn or_throw<'a, C: Context<'a>>(self, cx: &mut C) -> NeonResult<T>;
}

pub fn handle_exception<F: FnOnce() -> R + panic::UnwindSafe, R>(func: F) -> Result<R> {
  match panic::catch_unwind(func) {
    Ok(res) => Ok(res),
    Err(err) => {
      if let Some(string) = err.downcast_ref::<String>() {
        return Err(string.clone());
      } else if let Some(string) = err.downcast_ref::<&'static str>() {
        return Err(string.to_string());
      }
      return Err(format!("Error: {:?}", err));
    }
  }
}

pub fn hide_exceptions() {
  panic::set_hook(Box::new(|_| {}));
}

impl<T> NeonResultConvertible<T> for Result<T> {
  fn or_throw<'a, C: Context<'a>>(self, cx: &mut C) -> NeonResult<T> {
    match self {
      Ok(val) => Ok(val),
      Err(err) => cx.throw_error(err)
    }
  }
}
