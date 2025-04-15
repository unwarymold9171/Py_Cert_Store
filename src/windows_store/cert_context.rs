use std::io::{Result, Error};
use std::os::raw::c_void;
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

// May want to make this a python class and allow some of the functions to be called from python (like extensions)
impl CertContext {
    // NOTE: This function may be needed to provide private bytes for the certificate
    // #[allow(dead_code)]
    fn get_bytes(&self, prop:u32) -> Result<Vec<u8>> {
        
        let mut len = 0;
        let ret = unsafe {
            Cryptography::CertGetCertificateContextProperty(
                self.0,
                prop,
                ptr::null_mut(),
                &mut len
            )
        };

        if ret == 0 {
            return Err(Error::last_os_error());
        }

        let mut buf = vec![0u8; len as usize];
        let ret = unsafe {
            Cryptography::CertGetCertificateContextProperty(
                self.0,
                prop,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len
            )
        };

        if ret == 0 {
            return Err(Error::last_os_error());
        }

            return Ok(buf);
    }

    fn get_string(&self, prop:u32) -> Result<String> {
        let mut len = 0;
        let ret = unsafe {
            Cryptography::CertGetCertificateContextProperty(
                self.0,
                prop,
                ptr::null_mut(),
                &mut len
            )
        };

        if ret == 0 {
            return Err(Error::last_os_error());
        }

        // len is byte length, and it is being used to allocate to u16 pairs (2 bytes)
        let amt = (len / 2) as usize;
        let mut buf = vec![0u16; amt];
        let ret = unsafe {
            Cryptography::CertGetCertificateContextProperty(
                self.0,
                prop,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len
            )
        };

        if ret == 0 {
            return Err(Error::last_os_error());
        }

        return Ok(OsString::from_wide(&buf[..amt-1]).to_string_lossy().to_string());
    }

    pub fn friendly_name(&self) -> Result<String> {
        self.get_string(Cryptography::CERT_FRIENDLY_NAME_PROP_ID)
    }

    // TODO: Issue #3
    pub fn valid_from(&self) -> Result<String> {
        let file_time = unsafe {
            (*self.0).pCertInfo.as_ref().unwrap().NotBefore
        };

        // This is the wrong way to convert the FILETIME to a DateTime
        // and uses deprecated functions
        //
        // Current output: 2104-08-10T18:54:56Z
        // Should be: 2024-12-16T07:41:21Z
        let output = chrono::DateTime::<chrono::Utc>::from_utc(
            chrono::NaiveDateTime::from_timestamp(file_time.dwLowDateTime as i64, file_time.dwHighDateTime as u32),
            chrono::Utc
        ).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .parse::<String>()
            .map_err(|_| Error::new(std::io::ErrorKind::InvalidData, "Failed to parse file time"))?;

        return Ok(output);
    }

    // TODO: Issue #3
    pub fn valid_to(&self) -> Result<String> {
        let file_time = unsafe {
            (*self.0).pCertInfo.as_ref().unwrap().NotAfter
        };

        // This is the wrong way to convert the FILETIME to a DateTime
        // and uses deprecated functions
        //
        // Current output: 2032-09-18T23:06:40Z
        // Should be: 2025-12-16T07:41:21Z
        let output = chrono::DateTime::<chrono::Utc>::from_utc(
            chrono::NaiveDateTime::from_timestamp(file_time.dwLowDateTime as i64, file_time.dwHighDateTime as u32),
            chrono::Utc
        ).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .parse::<String>()
            .map_err(|_| Error::new(std::io::ErrorKind::InvalidData, "Failed to parse file time"))?;

        return Ok(output);
    }

    // TODO: Issue #3
    pub fn issuer(&self) -> Result<String> {
        let len = 500;
        let amt = (len / 2) as usize;
        let mut buf = vec![0u16; amt as usize];
        let ret = unsafe {
            Cryptography::CertGetNameStringW(
                self.0,
                Cryptography::CERT_NAME_RDN_TYPE, // This I knows works: Cryptography::CERT_NAME_RDN_TYPE
                Cryptography::CERT_NAME_ISSUER_FLAG,
                Cryptography::szOID_ORGANIZATION_NAME as *const c_void,
                buf.as_mut_ptr(),
                len
            )
        };

        // Notes:
        // Cryptography::CERT_NAME_RDN_TYPE appears to pull everything from the certificate
        // Cryptography::CERT_NAME_ATTR_TYPE appears to pull the "O" from the certificate
        // Cryptography::CERT_NAME_SIMPLE_DISPLAY_TYPE appears to pull the "CN" from the certificate <- This appears to be the correct one to use for the desired output
        // Cryptography::CERT_NAME_FRIENDLY_DISPLAY_TYPE is the save value pulled by self.friendly_name


        if ret == 0 {
            return Err(Error::last_os_error());
        }

        let mut out_string = OsString::from_wide(&buf[..amt-1]).to_string_lossy().to_string();
        out_string = out_string.replace("\0", ""); // Remove null terminators
        out_string = out_string.replace("\r\n", ", "); // Replace new lines with commas
        // TODO: Finish manupulating the string to get a format that can be read easily by the user (example: "CN=John Doe, OU=Engineering, O=Company, L=City, S=State, C=Country")

        return Ok(out_string);
    }

    // Pulls the Name of the certificate 
    pub fn name(&self) -> Result<String> {
        let len = 500;
        let amt = (len / 2) as usize;
        let mut buf = vec![0u16; amt as usize];
        let ret = unsafe {
            Cryptography::CertGetNameStringW(
                self.0,
                Cryptography::CERT_NAME_RDN_TYPE, // This I knows works: Cryptography::CERT_NAME_RDN_TYPE
                0,
                Cryptography::szOID_ORGANIZATION_NAME as *const c_void,
                buf.as_mut_ptr(),
                len
            )
        };

        // Notes:
        // Cryptography::CERT_NAME_RDN_TYPE appears to pull everything from the certificate
        // Cryptography::CERT_NAME_ATTR_TYPE appears to pull the "O" from the certificate
        // Cryptography::CERT_NAME_SIMPLE_DISPLAY_TYPE appears to pull the "CN" from the certificate
        // Cryptography::CERT_NAME_FRIENDLY_DISPLAY_TYPE is the save value pulled by self.friendly_name


        if ret == 0 {
            return Err(Error::last_os_error());
        }

        let mut out_string = OsString::from_wide(&buf[..amt-1]).to_string_lossy().to_string();
        out_string = out_string.replace("\0", ""); // Remove null terminators
        out_string = out_string.replace("\r\n", ", "); // Replace new lines with commas
        // TODO: Finish manupulating the string to get a format that can be read easily by the user (example: "CN=John Doe, OU=Engineering, O=Company, L=City, S=State, C=Country")

        return Ok(out_string);
    }

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

    pub fn has_extension_with_property(&self, extension_oid:*const u8, extension_value:Option<&str>) -> Result<bool> {
        
        let key_usage = unsafe {
            Cryptography::CertFindExtension(
                extension_oid,
                (*(*self.0).pCertInfo).cExtension,
                (*(*self.0).pCertInfo).rgExtension,
            )
        };

        if key_usage.is_null() {
            return Ok(false); // Not finding the target usage should just return false
        }

        match extension_value {
            Some(value) => {
                let mut str_sz = 0;
                let ret = unsafe {
                    Cryptography::CryptFormatObject(
                        Cryptography::X509_ASN_ENCODING,
                        0,
                        0,
                        ptr::null_mut(),
                        extension_oid,
                        (*key_usage).Value.pbData,
                        (*key_usage).Value.cbData,
                        ptr::null_mut(),
                        &mut str_sz,
                    )
                };

                if ret == 0 {
                    return Err(Error::last_os_error());
                }

                let mut buff = Vec::with_capacity((str_sz / 2) as usize);
                unsafe { buff.set_len((str_sz / 2) as usize) };
                let ret = unsafe {
                    Cryptography::CryptFormatObject(
                        Cryptography::X509_ASN_ENCODING,
                        0,
                        0,
                        ptr::null_mut(),
                        extension_oid,
                        (*key_usage).Value.pbData,
                        (*key_usage).Value.cbData,
                        buff.as_mut_ptr() as *mut _,
                        &mut str_sz,
                    )
                };

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
