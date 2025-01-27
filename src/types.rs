use std::marker::PhantomData;

use dataview::Pod;

#[repr(transparent)]
pub struct Pointer<T: ?Sized = ()> {
    pub inner: u64,
    phantom_data: PhantomData<fn() -> T>,
}

unsafe impl<T: ?Sized + 'static> Pod for Pointer<T> {}
