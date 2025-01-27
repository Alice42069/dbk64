use std::marker::PhantomData;

use dataview::Pod;

#[repr(transparent)]
#[derive(Debug, Default, Clone, Hash, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pointer<T: ?Sized = ()> {
    pub inner: u64,
    phantom_data: PhantomData<fn() -> T>,
}

unsafe impl<T: ?Sized + 'static> Pod for Pointer<T> {}

impl<T: ?Sized> From<u64> for Pointer<T> {
    fn from(address: u64) -> Pointer<T> {
        Pointer { inner: address, phantom_data: PhantomData }
    }
}