#![cfg(windows)]

macro_rules! inner_impl {
    ($t:path, $inner:ty) => {
        impl crate::windows_store::Inner<$inner> for $t {
            unsafe fn from_inner(t: $inner) -> Self {
                $t(t)
            }

            fn as_inner(&self) -> $inner {
                self.0
            }

            fn get_mut(&mut self) -> &mut $inner {
                &mut self.0
            }
        }

        // TODO: This was throwing errors, and is not being used. may remove
        // impl crate::windows_store::InnerType for $inner {
        //     unsafe fn from_ptr(t: *mut ::std::os::raw::c_void) -> $t {
        //         $t(t as _)
        //     }

        //     unsafe fn as_ptr(&self) -> *mut ::std::os::raw::c_void {
        //         self.0 as *mut _
        //     }
        // }
    };
}

pub mod cert_context;
pub mod cert_store;

trait Inner<T> {
    unsafe fn from_inner(t: T) -> Self;

    fn as_inner(&self) -> T;

    #[allow(dead_code)]
    fn get_mut(&mut self) -> &mut T;
}

pub trait InnerType {
    unsafe fn from_ptr(ptr: *mut ::std::os::raw::c_void) -> Self;

    unsafe fn as_ptr(&self) -> *mut ::std::os::raw::c_void;
}
