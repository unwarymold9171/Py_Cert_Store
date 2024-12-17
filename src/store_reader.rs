#[deny(clippy::unwrap_used)]
#[deny(clippy::expect_used)]
#[deny(clippy::panic)]

use pyo3::prelude::*;
use pyo3::exceptions::{PyOSError, PyRuntimeError};

use crate::windows_store::cert_store::CertStore;
use crate::windows_store::cert_context::CertContext;
use crate::exceptions::CertNotExportable;


#[allow(unused_variables)] // TODO: Remove
#[pyfunction]
#[pyo3(signature = (store="My", extention_name=None, extention_value=None))]
/// Find a certificate in the Windows Certificate Store by its extention
pub fn find_windows_cert_by_extention(store:&str, extention_name:Option<&str>, extention_value:Option<&str>) -> PyResult<String>  {
    // TODO: Change return type to either Bytes/CertContext/Dict
    // TODO: Clean these notes and todos
    if !cfg!(windows){
        return Err(PyOSError::new_err("The `find_windows_cert_by_extention` function can only called from a Windows computer."));
    }

    let certs = match CertStore::open_current_user(store){
        Ok(certs) => certs,
        Err(_) => {
            return Err(PyRuntimeError::new_err("Could not open the certificate store."));
        }
    };

    let mut targeted_cert: Option<CertContext> = None;

    for cert in certs.certs() {
        let friendly_name = match cert.friendly_name() {
            Ok(name) => name,
            Err(_) => {
                "No_Name".to_string()
            }
        };

        match cert.is_time_valid() {
            Ok(valid) => {
                if !valid {
                    continue;
                }
            },
            Err(_) => {
                continue;
            }
        }

        match cert.has_digital_signature() { // TODO: Alter this function to take a parameter
            Ok(has) => {
                if has {
                    targeted_cert = Some(cert);
                }
                continue;
            },
            Err(_) => {
                continue;
            }
        };

    }

    match targeted_cert {
        None => {
            return Err(PyRuntimeError::new_err("No Valid Certificates found."));
        },
        Some(cert) => {
            match cert.is_exportable() {
                Ok(exportable) => {
                    if !exportable {
                        return Err(CertNotExportable::new_err("The certificate is not exportable."));
                    }
                },
                Err(_) => {
                    return Err(PyRuntimeError::new_err("Could not determine if the certificate is exportable."));
                    // NOTE: may change this error to a custom error
                }

            }
            // TODO
    //         let private_options = cert.private_key();
    //         let private = private_options.acquire().unwrap();

    //         match private {
    //             PrivateKey::CryptProv(_) => {
    //                 println!("CryptKey");
    //                 // TODO: I believe this is an error state here
    //             },
    //             PrivateKey::NcryptKey(key) => {
    //                 println!("NcryptKey");
    //                 // TODO: This is what the sample is
    //             }
    //         }

            // return Ok(key_usage.to_string());
            return Ok("Found a certificate.".to_string());
        }
    }
    // Ok("".to_string())

}
