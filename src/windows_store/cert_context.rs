use std::io::{Result, Error};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::ffi::OsString;
use windows_sys::Win32::Security::Cryptography;
use windows_sys::Win32::System::Time;
use windows_sys::Win32::Foundation::{SYSTEMTIME, FILETIME};


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

    fn get_context_string(&self, prop:u32) -> Result<String> {
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

    fn get_name_string(&self, prop: u32) -> Result<String> {
        let len = 500;
        let amt = (len / 2) as usize;
        let mut buf = vec![0u16; amt as usize];
        let ret = unsafe {
            Cryptography::CertGetNameStringW(
                self.0,
                Cryptography::CERT_NAME_RDN_TYPE, // This I knows works: Cryptography::CERT_NAME_RDN_TYPE
                prop,
                Cryptography::szOID_ORGANIZATION_NAME as *const std::ffi::c_void,
                buf.as_mut_ptr(),
                len
            )
        };

        // Notes:
        // Cryptography::CERT_NAME_RDN_TYPE appears to pull everything from the certificate
        // Cryptography::CERT_NAME_ATTR_TYPE appears to pull the "O" from the certificate
        // Cryptography::CERT_NAME_SIMPLE_DISPLAY_TYPE appears to pull the "CN" from the certificate
        // Cryptography::CERT_NAME_FRIENDLY_DISPLAY_TYPE is the save value pulled by self.friendly_name

        // Thoughts:
        // I may need to itterate over a set of dwtype values and "title" values to get the format I want

        if ret == 0 {
            return Err(Error::last_os_error());
        }

        let mut out_string = OsString::from_wide(&buf[..amt-1]).to_string_lossy().to_string();
        out_string = out_string.replace("\0", ""); // Remove null terminators
        out_string = out_string.replace("\r\n", ", "); // Replace new lines with commas
        // TODO: Finish manupulating the string to get a format that can be read easily by the user (example: "CN=John Doe, OU=Engineering, O=Company, L=City, S=State, C=Country")

        return Ok(out_string);
    }

    fn get_date_string(&self, time_val:FILETIME) -> Result<String> {
        let mut system_time = SYSTEMTIME {
            wYear: 0,
            wMonth: 0,
            wDayOfWeek: 0,
            wDay: 0,
            wHour: 0,
            wMinute: 0,
            wSecond: 0,
            wMilliseconds: 0,
        };

        let ret = unsafe {
            Time::FileTimeToSystemTime(
                &time_val as *const FILETIME,
                &mut system_time as *mut SYSTEMTIME,
            )
        };

        if ret == 0 {
            return Err(Error::last_os_error());
        }

        let native_date = chrono::NaiveDate::from_ymd_opt(
            system_time.wYear as i32,
            system_time.wMonth as u32,
            system_time.wDay as u32
        );
        let native_time = chrono::NaiveTime::from_hms_opt(
            system_time.wHour as u32,
            system_time.wMinute as u32,
            system_time.wSecond as u32
        );

        let native_datetime = chrono::NaiveDateTime::new(
            native_date.unwrap(),
            native_time.unwrap()
        );
        let datetime = native_datetime.and_utc();

        let output = datetime.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .parse::<String>()
            .map_err(|_| Error::new(std::io::ErrorKind::InvalidData, "Failed to parse file time"))?;

        return Ok(output);
    }

    pub fn friendly_name(&self) -> Result<String> {
        self.get_context_string(Cryptography::CERT_FRIENDLY_NAME_PROP_ID)
    }

    /// Pulls a string representing the valid start date of the certificate.
    /// Returns a string in the format of "YYYY-MM-DDTHH:MM:SSZ"
    pub fn valid_from(&self) -> Result<String> {
        let file_time = unsafe {
            (*self.0).pCertInfo.as_ref().unwrap().NotBefore
        };

        return self.get_date_string(file_time);
    }

    /// Pulls a string representing the expiration date of the certificate.
    /// Returns a string in the format of "YYYY-MM-DDTHH:MM:SSZ"
    pub fn valid_to(&self) -> Result<String> {
        let file_time = unsafe {
            (*self.0).pCertInfo.as_ref().unwrap().NotAfter
        };

        return self.get_date_string(file_time);
    }

    /// Pulls the Issuer of the certificate.
    pub fn issuer(&self) -> Result<String> {
        return self.get_name_string(Cryptography::CERT_NAME_ISSUER_FLAG);
    }

    /// Pulls the Name of the certificate.
    pub fn name(&self) -> Result<String> {
        return self.get_name_string(0);
    }

    /// Pulls the private key from the certificate.
    /// Returns a vector of bytes representing the private key.
    ///
    /// This function will cause an error if the certificate is not exportable.
    pub fn private_key(&self) -> Result<Vec<u8>> {
        self.get_bytes(Cryptography::CERT_KEY_PROV_INFO_PROP_ID)
    }

    /// Checks if the certificate is still valid.
    /// Returns true if the certificate is valid, false otherwise.
    pub fn is_time_valid(&self) -> Result<bool> {
        let ret = unsafe {
            Cryptography::CertVerifyTimeValidity(
                ptr::null_mut(),
                (*self.0).pCertInfo
            )
        };
        Ok(ret == 0)
    }

    /// Checks if the certificate is exportable.
    /// Returns true if the certificate is exportable, false otherwise.
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
