use neon::borrow::*;
use neon::types::BinaryData;
use std::slice;

pub struct MutBufferPtr {
  pub size: usize,
  pub ptr: *mut u8
}

impl MutBufferPtr {
  pub fn from(slice: &mut [u8]) -> Self {
    MutBufferPtr { ptr: slice.as_mut_ptr(), size: slice.len() }
  }

  pub fn as_sized_slice<'a>(&'a self, size: usize) -> &'a mut [u8] {
    if size > self.size { panic!("Size {} >= {}", size, self.size) }
    unsafe {
      slice::from_raw_parts_mut(self.ptr, size)
    }
  }
}

pub struct BufferPtr {
  pub size: usize,
  pub ptr: *const u8
}

impl<'a> From<RefMut<'a, BinaryData<'a>>> for MutBufferPtr {
  fn from(reference: RefMut<'a, BinaryData<'a>>) -> Self {
    MutBufferPtr { size: reference.len(), ptr: reference.as_mut_slice::<u8>().as_mut_ptr() }
  }
}

impl<'a> From<Ref<'a, BinaryData<'a>>> for BufferPtr {
  fn from(reference: Ref<'a, BinaryData<'a>>) -> Self {
    BufferPtr { size: reference.len(), ptr: reference.as_slice::<u8>().as_ptr() }
  }
}