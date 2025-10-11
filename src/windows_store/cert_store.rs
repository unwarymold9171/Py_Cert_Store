// Copyright 2025 Niky H. (Unwarymold9171)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#[deny(clippy::unwrap_used)]
#[deny(clippy::expect_used)]
#[deny(clippy::panic)]

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

impl CertStore {
    pub fn open_current_user(store:&str) -> Result<CertStore> {
        unsafe {
            let data = OsStr::new(store)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let store = Cryptography::CertOpenStore(
                Cryptography::CERT_STORE_PROV_SYSTEM_W,
                Cryptography::CERT_QUERY_ENCODING_TYPE::default(),
                Cryptography::HCRYPTPROV_LEGACY::default(),
                Cryptography::CERT_SYSTEM_STORE_CURRENT_USER_ID
                  << Cryptography::CERT_SYSTEM_STORE_LOCATION_SHIFT,
                data.as_ptr() as *mut _
            );
            if !store.is_null() {
                Ok(CertStore(store))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    pub fn open_local_machine(store:&str) -> Result<CertStore> {
        unsafe {
            let data = OsStr::new(store)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let store = Cryptography::CertOpenStore(
                Cryptography::CERT_STORE_PROV_SYSTEM_W,
                Cryptography::CERT_QUERY_ENCODING_TYPE::default(),
                Cryptography::HCRYPTPROV_LEGACY::default(),
                Cryptography::CERT_SYSTEM_STORE_LOCAL_MACHINE_ID
                  << Cryptography::CERT_SYSTEM_STORE_LOCATION_SHIFT,
                data.as_ptr() as *mut _
            );
            if !store.is_null() {
                Ok(CertStore(store))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    pub fn certs<'a>(&'a self) -> CertIter<'a> {
        CertIter {
            store: self,
            cur: None
        }
    }
}
