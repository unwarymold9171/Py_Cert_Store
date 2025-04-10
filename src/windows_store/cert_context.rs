use std::io::{Result, Error};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::ffi::OsString;
use windows_sys::Win32::Security::Cryptography;


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

// May want to make this a python class and allow some of the functions to be called from python (like extentions)
impl CertContext {
    // NOTE: This function may be needed to provide private bytes for the certificate
    // #[allow(dead_code)]
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

    pub fn name(&self) -> Result<String> {
        self.get_string(Cryptography::CERT_NAME_SIMPLE_DISPLAY_TYPE)
    }

    // TODO: Issue #3
    // pub fn valid_from(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_VALID_FROM_PROP_ID)
    // }

    // TODO: Issue #3
    // pub fn valid_to(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_VALID_TO_PROP_ID)
    // }

    // TODO: Issue #3
    // pub fn issuer(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_ISSUER_PROP_ID)
    // }

    // TODO: Issue #3
    // pub fn subject(&self) -> Result<String> {
    //     self.get_string(Cryptography::CERT_SUBJECT_PROP_ID)
    // }

    pub fn private_key(&self) -> Result<Vec<u8>> {
        self.get_bytes(Cryptography::CERT_KEY_PROV_INFO_PROP_ID)
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

        if ret == 0 {
            return Err(Error::last_os_error());
        }

        Ok(key_spec == Cryptography::AT_KEYEXCHANGE)
    }

    pub fn has_extention_with_property(&self, extention_oid:*const u8, extention_value:Option<&str>) -> Result<bool> {
        unsafe {
            let key_usage = Cryptography::CertFindExtension(
                extention_oid,
                (*(*self.0).pCertInfo).cExtension,
                (*(*self.0).pCertInfo).rgExtension,
            );

            if key_usage.is_null() {
                return Ok(false); // Not finding the target usage should just return false
            }

            match extention_value {
                Some(value) => {
                    let mut str_sz = 0;
                    let ret = Cryptography::CryptFormatObject(
                        Cryptography::X509_ASN_ENCODING,
                        0,
                        0,
                        ptr::null_mut(),
                        extention_oid,
                        (*key_usage).Value.pbData,
                        (*key_usage).Value.cbData,
                        ptr::null_mut(),
                        &mut str_sz,
                    );

                    if ret == 0 {
                        return Err(Error::last_os_error());
                    }

                    let mut buff = Vec::with_capacity((str_sz / 2) as usize);
                    buff.set_len((str_sz / 2) as usize);
                    let ret = Cryptography::CryptFormatObject(
                        Cryptography::X509_ASN_ENCODING,
                        0,
                        0,
                        ptr::null_mut(),
                        extention_oid,
                        (*key_usage).Value.pbData,
                        (*key_usage).Value.cbData,
                        buff.as_mut_ptr() as *mut _,
                        &mut str_sz,
                    );

                    if ret == 0 {
                        return Err(Error::last_os_error());
                    }

                    let buff = String::from_utf16_lossy(&buff);
                    return Ok(buff.contains(value));
                }
                None => {
                    return Ok(true);
                }
            }

            
        }
    }
}
