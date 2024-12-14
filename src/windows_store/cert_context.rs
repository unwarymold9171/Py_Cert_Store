use std::io::{Result, Error};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::ffi::OsString;
// use pyo3::prelude::*;
use windows_sys::Win32::Security::Cryptography;

// use crate::windows_store::cert_store::CertStore; // My not need this since I am only store to cert
// use crate::windows_store::Inner;

// #[derive(Copy, CLoner)]
// pub struct HashAlgorithm {
//     pub oid: &'static str,
//     pub name: &'static str,
// }

#[derive(Debug)]
pub struct CertContext(*const Cryptography::CERT_CONTEXT);

impl Clone for CertContext {
    fn clone(&self) -> CertContext {
        unsafe {
            CertContext(Cryptography::CertDuplicateCertificateContext(self.0))
        }
    }
}

inner_impl!(CertContext, *const Cryptography::CERT_CONTEXT);

impl CertContext {
    // NOTE: This function may not be used, but included until confirmed
    #[allow(dead_code)]
    fn get_bytes(&self, prop:u32) -> Result<Vec<u8>> {
        unsafe {
            let mut len = 0;
            let ret = Cryptography::CertGetCertificateContextProperty(
                self.0,
                prop,
                ptr::null_mut(),
                &mut len
            );

            if ret == 0 {
                return Err(Error::last_os_error());
            }

            let mut buf = vec![0u8; len as usize];
            let ret = Cryptography::CertGetCertificateContextProperty(
                self.0,
                prop,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len
            );

            if ret == 0 {
                return Err(Error::last_os_error());
            }

            return Ok(buf);
        }
    }

    fn get_string(&self, prop:u32) -> Result<String> {
        unsafe {
            let mut len = 0;
            let ret = Cryptography::CertGetCertificateContextProperty(
                self.0,
                prop,
                ptr::null_mut(),
                &mut len
            );

            if ret == 0 {
                return Err(Error::last_os_error());
            }

            // len is byte length, and it is being used to allocate to u16 pairs (2 bytes)
            let amt = (len / 2) as usize;
            let mut buf = vec![0u16; amt];
            let ret = Cryptography::CertGetCertificateContextProperty(
                self.0,
                prop,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len
            );

            if ret == 0 {
                return Err(Error::last_os_error());
            }

            return Ok(OsString::from_wide(&buf[..amt-1]).to_string_lossy().to_string());
        }
    }

    pub fn friendly_name(&self) -> Result<String> {
        self.get_string(Cryptography::CERT_FRIENDLY_NAME_PROP_ID)
    }

    pub fn is_time_valid(&self) -> Result<bool> {
        let ret = unsafe {
            Cryptography::CertVerifyTimeValidity(
                ptr::null_mut(),
                (*self.0).pCertInfo
            )
        };
        Ok(ret == 0)
    }

    // TODO: This function was auto generated, and need to be varified
    pub fn is_exportable(&self) -> Result<bool> {
        let mut key_spec = 0;
        let mut len = std::mem::size_of::<u32>() as u32;
        let ret = unsafe {
            Cryptography::CertGetCertificateContextProperty(
                self.0,
                Cryptography::CERT_KEY_SPEC_PROP_ID,
                &mut key_spec as *mut _ as *mut std::ffi::c_void,
                &mut len
            )
        };
        Ok(ret == 0)
    }
    

    // pub fn issuer(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_ISSUER_NAME_STR)
    // }

    // pub fn subject(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_SUBJECT_NAME_STR)
    // }

    // pub fn thumbprint(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_SHA1_HASH_PROP_ID)
    // }

    // pub fn valid_uses(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_KEY_PROV_INFO_PROP_ID)
    // }

    // pub fn private_key(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_KEY_PROV_INFO_PROP_ID)
    // }

    // pub fn public_key(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_PUBLIC_KEY_PROP_ID)
    // }

    // pub fn extended_key_usage(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_ENHKEY_USAGE_PROP_ID)
    // }

    // pub fn key_usage(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_KEY_USAGE_PROP_ID)
    // }

    // pub fn enhanced_key_usage(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_ENHKEY_USAGE_PROP_ID)
    // }

    // pub fn key_spec(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_KEY_SPEC_PROP_ID)
    // }

    // pub fn key_context(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_KEY_CONTEXT_PROP_ID)
    // }


}
