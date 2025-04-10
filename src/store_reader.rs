#[deny(clippy::unwrap_used)]
#[deny(clippy::expect_used)]
#[deny(clippy::panic)]

use std::collections::HashMap;

use pyo3::prelude::*; // TODO: properly import this module
use pyo3::exceptions::{PyOSError, PyRuntimeError};
// use pyo3::types::IntoPyDict; // TODO: Look into having a enum that is converted to a PyObject automatically
use windows_sys::Win32::Security::Cryptography;

use crate::windows_store::cert_store::CertStore;
use crate::windows_store::cert_context::CertContext;
use crate::exceptions::CertNotExportable;

// Replace this with the proper pyo3 import so that Python interprets the dictionary correctly
// #[pyclass]
// pub enum Value {
//     String(String),
//     Bytes(Vec<u8>), // This needs to be a Cow<[u8]> to be converted to a PyBytes value
// }


#[pyfunction]
#[pyo3(signature = (store="My", extension_oid=None, extension_value=None))]
/// Find a certificate in the Windows Certificate Store by its extension
#[allow(unused_variables)]
pub fn find_windows_cert_by_extension(store:&str, extension_oid:Option<u8>, extension_value:Option<&str>) -> PyResult<HashMap<String, String>> {
    if !cfg!(windows) {
        return Err(PyOSError::new_err("The \"find_windows_cert_by_extension\" function can only be called from a Windows computer."));
    }

    let certs = CertStore::open_current_user(store).map_err(|_| {
        PyRuntimeError::new_err("Could not open the certificate store.")
    })?;

    let mut targeted_cert: Option<CertContext> = None;

    for cert in certs.certs() {
        match cert.is_time_valid() {
            Ok(valid) => {
                if !valid {
                    continue;
                }
            },
            Err(_) => continue // Assume that the cert is not valid and jump to the next one
        }

        // TODO: Either with Python or a HashMap in Rust, match the OID from Python's Cryptography x509 to the valid OID in Windows
        // let extension_oid = match extension_oid {
        //     Some(oid) => {
        //     },
        //     None => {}
        // }

        match cert.has_extension_with_property(Cryptography::szOID_KEY_USAGE, extension_value) { // TODO: Alter this function to take other parameters
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

    let mut output_dict: HashMap<String, String> = HashMap::new();

    match targeted_cert {
        None => {
            return Err(PyRuntimeError::new_err("No valid certificates found."));
        },
        Some(cert) => {
            match cert.is_exportable() {
                Ok(exportable) => {
                    if !exportable {
                        return Err(CertNotExportable::new_err("The certificate is not exportable."));
                    }
                },
                Err(_) => {
                    return Err(PyRuntimeError::new_err("Unable to determine if the certificate is exportable."));
                    // NOTE: may change this error to a custom error
                }

            }

            let friendly_name = cert.friendly_name().unwrap_or("".to_string());
            output_dict.insert("FriendlyName".to_string(), friendly_name);


            let private_options = match cert.private_key() {
                Err(_) => {
                    return Err(PyRuntimeError::new_err("Could not get the private key."));
                },
                Ok(private_key) => private_key
            };
            // let private = private_options.acquire().unwrap();

            // match private {
            //     PrivateKey::CryptProv(_) => {
            //         println!("CryptKey");
            //         // TODO: I believe this is an error state here
            //     },
            //     PrivateKey::NcryptKey(key) => {
            //         println!("NcryptKey");
            //         // TODO: This is what the sample is
            //     }
            // }



            return Ok(output_dict);
        }
    }

    // Err(PyRuntimeError::new_err("Invalid state reached."))

}
