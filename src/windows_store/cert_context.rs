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
        ).ok_or_else(|| Error::new(std::io::ErrorKind::InvalidData, "Invalid date components"))?;
        let native_time = chrono::NaiveTime::from_hms_opt(
            system_time.wHour as u32,
            system_time.wMinute as u32,
            system_time.wSecond as u32
        ).ok_or_else(|| Error::new(std::io::ErrorKind::InvalidData, "Invalid date components"))?;

        let native_datetime = chrono::NaiveDateTime::new(native_date, native_time);
        let datetime = native_datetime.and_utc();

        let output = datetime.format("%m/%d/%Y %I:%M:%S %p").to_string();

        return Ok(output);
    }

    pub fn friendly_name(&self) -> Result<String> {
        self.get_context_string(Cryptography::CERT_FRIENDLY_NAME_PROP_ID)
    }

    /// Pulls a string representing the valid start date of the certificate.
    /// Returns a string in the format of "MM/DD/YYYY HH:MM:SS AM/PM"
    pub fn valid_from(&self) -> Result<String> {
        let file_time = unsafe {
            (*self.0).pCertInfo.as_ref().unwrap().NotBefore
        };

        self.get_date_string(file_time)
    }

    /// Pulls a string representing the expiration date of the certificate.
    /// Returns a string in the format of "MM/DD/YYYY HH:MM:SS AM/PM"
    pub fn valid_to(&self) -> Result<String> {
        let file_time = unsafe {
            (*self.0).pCertInfo.as_ref().unwrap().NotAfter
        };

        self.get_date_string(file_time)
    }

    /// Pulls the Issuer of the certificate.
    pub fn issuer(&self) -> Result<String> {
        self.get_name_string(Cryptography::CERT_NAME_ISSUER_FLAG)
    }

    /// Pulls the Name of the certificate.
    pub fn name(&self) -> Result<String> {
        self.get_name_string(0)
    }

    /// Pulls the private key from the certificate.
    /// Returns a vector of bytes representing the private key.
    pub fn private_key(&self) -> Result<Vec<u8>> {
        let mut key_handle: Cryptography::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = 0;
        let mut key_spec = 0;
        let mut free_key = 0;
    
        // Acquire the private key handle
        let ret = unsafe {
            Cryptography::CryptAcquireCertificatePrivateKey(
                self.0,
                Cryptography::CRYPT_ACQUIRE_CACHE_FLAG | Cryptography::CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                ptr::null_mut(),
                &mut key_handle,
                &mut key_spec,
                &mut free_key,
            )
        };
    
        if ret == 0 {
            return Err(Error::last_os_error());
        }
    
        // Ensure the key handle is freed if necessary
        let _guard = if free_key != 0 {
            Some(scopeguard::guard(key_handle, |handle| {
                unsafe {
                    Cryptography::NCryptFreeObject(handle as Cryptography::NCRYPT_HANDLE);
                }
            }))
        } else {
            None
        };
    
        let mut key_blob_len = 0;
    
        // Export the private key based on the key type
        if key_spec == 0 || key_spec == 0xFFFFFFFF {
            // CNG key: Use NCryptExportKey
            let ret = unsafe {
                Cryptography::NCryptExportKey(
                    key_handle as Cryptography::NCRYPT_KEY_HANDLE,
                    0,
                    Cryptography::BCRYPT_PRIVATE_KEY_BLOB,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    &mut key_blob_len,
                    0,
                )
            };
    
            if ret != 0 {
                return Err(Error::last_os_error());
            }
    
            let mut key_blob = vec![0u8; key_blob_len as usize];
            let ret = unsafe {
                Cryptography::NCryptExportKey(
                    key_handle as Cryptography::NCRYPT_KEY_HANDLE,
                    0,
                    Cryptography::BCRYPT_PRIVATE_KEY_BLOB,
                    ptr::null_mut(),
                    key_blob.as_mut_ptr(),
                    key_blob_len,
                    &mut key_blob_len,
                    0,
                )
            };
    
            if ret != 0 {
                return Err(Error::last_os_error());
            }
    
            Ok(key_blob)
        } else {
            // CSP key: Use CryptExportKey
            let ret = unsafe {
                Cryptography::CryptExportKey(
                    key_handle,
                    0,
                    Cryptography::PRIVATEKEYBLOB,
                    0,
                    ptr::null_mut(),
                    &mut key_blob_len,
                )
            };
    
            if ret == 0 {
                return Err(Error::last_os_error());
            }
    
            let mut key_blob = vec![0u8; key_blob_len as usize];
            let ret = unsafe {
                Cryptography::CryptExportKey(
                    key_handle,
                    0,
                    Cryptography::PRIVATEKEYBLOB,
                    0,
                    key_blob.as_mut_ptr(),
                    &mut key_blob_len,
                )
            };
    
            if ret == 0 {
                return Err(Error::last_os_error());
            }
    
            Ok(key_blob)
        }
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
    /// 
    // TODO: Add a check for the CSP key (key_spec != 0 && key_spec != 0xFFFFFFFF)
    pub fn is_exportable(&self) -> Result<bool> {
        let mut key_handle: Cryptography::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = 0;
        let mut key_spec = 0;
        let mut free_key = 0;

        // Acquire the private key handle
        let ret = unsafe {
            Cryptography::CryptAcquireCertificatePrivateKey(
                self.0,
                Cryptography::CRYPT_ACQUIRE_CACHE_FLAG | Cryptography::CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                ptr::null_mut(),
                &mut key_handle,
                &mut key_spec,
                &mut free_key,
            )
        };

        if ret == 0 {
            return Err(Error::last_os_error());
        }

        // Ensure the key handle is freed if necessary
        if free_key != 0 {
            Some(scopeguard::guard(key_handle, |handle| {
                unsafe {
                    Cryptography::NCryptFreeObject(handle as Cryptography::NCRYPT_HANDLE);
                }
            }))
        } else {
            None
        };

        if key_spec == 0 || key_spec == 0xFFFFFFFF {
            // println!("Key is a CNG key. Using NCryptExportKey.");

            // DEBUG
            /*
            // Retrieve the key storage provider name
            let mut provider_name_len = 0;
            let ret = unsafe {
                Cryptography::NCryptGetProperty(
                    key_handle as Cryptography::NCRYPT_KEY_HANDLE,
                    Cryptography::NCRYPT_NAME_PROPERTY,
                    ptr::null_mut(),
                    0,
                    &mut provider_name_len,
                    0,
                )
            };

            if ret == 0 {
                let mut provider_name = vec![0u16; (provider_name_len / 2) as usize];
                let ret = unsafe {
                    Cryptography::NCryptGetProperty(
                        key_handle as Cryptography::NCRYPT_KEY_HANDLE,
                        Cryptography::NCRYPT_NAME_PROPERTY,
                        provider_name.as_mut_ptr() as *mut _,
                        provider_name_len,
                        &mut provider_name_len,
                        0,
                    )
                };

                if ret == 0 {
                    let provider_name = String::from_utf16_lossy(&provider_name);
                    println!("Key storage provider: {}", provider_name);
                } else {
                    println!("Failed to retrieve key storage provider name.");
                }
            } else {
                println!("Failed to retrieve key storage provider name length.");
            }
            */
            // END DEBUG

            let mut key_blob_len = 0;

            // Attempt to export the key
            let ret = unsafe {
                Cryptography::NCryptExportKey(
                    key_handle as Cryptography::NCRYPT_KEY_HANDLE,
                    0,
                    Cryptography::BCRYPT_PRIVATE_KEY_BLOB,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    &mut key_blob_len,
                    0,
                )
            };

            println!("ret: {:#}", ret);

            // if ret != 0 {
            //     println!("Certificate not exportable according to NCryptExportKey.");
            //     return Ok(false); // Key is not exportable
            // }
            // return Ok(true);
            if ret == 0 {
                // println!("Key is exportable.");
                return Ok(true);
            } else if ret == -2146893783 { // NTE_BAD_KEY_STATE
                // println!("Key is not exportable (NTE_BAD_KEY_STATE).");
                return Ok(false);
            } else {
                return Err(Error::last_os_error());
            }
        }

        // This section will need to be modified to handle the CSP key case
        println!("CSP key detected. Handle not implemented.");
        // return Err(PyNotImplementedError::new_err("CSP key detected. Handle not implemented.")); // cannot use this error type here
        return Ok(false); // Passing false for now, but this will be implemented later

        // TODO: Handle the case where the key is a CSP key (key_spec != 0 && key_spec != 0xFFFFFFFF)
        // This should be the correct handling for CSP keys, but it needs to be checked

        // Attempt to export the key
        // let mut key_blob_len = 0;
        // let ret = unsafe {
        //     Cryptography::CryptExportKey(
        //         key_handle,
        //         0,
        //         Cryptography::PRIVATEKEYBLOB,
        //         0,
        //         ptr::null_mut(),
        //         &mut key_blob_len,
        //     )
        // };

        // if ret == 0 {
        //     let error = Error::last_os_error();
        //     if error.raw_os_error() == Some(0x57) { // ERROR_INVALID_PARAMETER
        //         // println!("Key is not exportable.");
        //         return Ok(false); // Key is not exportable
        //     }
        //     // println!("Error occured on CryptExportKey call.");
        //     return Err(error);
        // }

        // Ok(true) // Key is exportable
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
