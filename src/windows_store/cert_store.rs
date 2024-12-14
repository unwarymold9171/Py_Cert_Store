use std::io::{Result, Error};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::mem;
use std::ffi::OsStr;
// use pyo3::prelude::*;
use windows_sys::Win32::Security::Cryptography;

use crate::windows_store::cert_context::CertContext;
use crate::windows_store::Inner;

pub struct CertStore(Cryptography::HCERTSTORE);

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe {
            Cryptography::CertCloseStore(
                self.0, 
                0
            );
        }
    }
}

pub struct CertIter<'a> {
    store: &'a CertStore,
    cur: Option<CertContext>
}

impl <'a> Iterator for CertIter<'a> {
    type Item = CertContext;

    fn next(&mut self) -> Option<CertContext> {
        unsafe {
            let cur = self.cur.take().map(|p| {
                let ptr = p.as_inner();
                mem::forget(p);
                ptr
            });
            let cur = cur.unwrap_or(ptr::null_mut());
            let next = Cryptography::CertEnumCertificatesInStore(self.store.0, cur);

            if next.is_null() {
                self.cur = None;
                return None;
            } else {
                let next = CertContext::from_inner(next);
                self.cur = Some(next.clone());
                Some(next)
            }
        }
    }
    
}

inner_impl!(CertStore, Cryptography::HCERTSTORE);

impl CertStore {
    pub fn open_current_user(store:&str) -> Result<CertStore> {
        unsafe {
            let data = OsStr::new(store)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let _store = Cryptography::CertOpenStore(
                Cryptography::CERT_STORE_PROV_FILENAME_W,
                Cryptography::CERT_QUERY_ENCODING_TYPE::default(),
                Cryptography::HCRYPTPROV_LEGACY::default(),
                Cryptography::CERT_SYSTEM_STORE_CURRENT_USER_ID
                  << Cryptography::CERT_SYSTEM_STORE_LOCATION_SHIFT,
                data.as_ptr() as *mut std::ffi::c_void
            );
            if _store.is_null() {
                return Err(Error::last_os_error());
            }
            Ok(CertStore(_store))
        }
    }

    pub fn certs(&self) -> CertIter {
        CertIter {
            store: self,
            cur: None
        }
    }


}
