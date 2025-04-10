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


// Replace this with the proper pyo3 import so that python interperets the dictionary right
// #[pyclass]
// pub enum Value {
//     String(String),
//     Bytes(Vec<u8>), // This needs to be a Cow<[u8]> to be converted to a PyBytes value
// }


#[pyfunction]
#[pyo3(signature = (store="My", extention_oid=None, extention_value=None))]
/// Find a certificate in the Windows Certificate Store by its extention
#[allow(unused_variables)]
pub fn find_windows_cert_by_extention(store:&str, extention_oid:Option<u8>, extention_value:Option<&str>) -> PyResult<HashMap<String, String>> {
    // TODO: Clean these notes and todos
    if !cfg!(windows){
        return Err(PyOSError::new_err("The `find_windows_cert_by_extention` function can only called from a Windows computer."));
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

        // TODO: either with python or a hashmap in rust, match the oid from Python's Cryptography x509 to the valid oid in windows
        // let extention_oid = match extention_oid {
        //     Some(oid) => oid,
        //     None => {
        //         // TODO: do not throw an error here, but skip the check
        //         return Err(PyRuntimeError::new_err("No extention OID provided."));
        //     }
        // };

        match cert.has_extention_with_property(Cryptography::szOID_KEY_USAGE, extention_value) { // TODO: Alter this function to take a parameter
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

    println!("Target Cert match case reached.");

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

            let friendly_name = cert.friendly_name().unwrap_or("".to_string());
            output_dict.insert("FriendlyName".to_string(), friendly_name);


            let private_options = match cert.private_key() {
                Err(_) => {
                    return Err(PyRuntimeError::new_err("Could not get the private key."));
                },
                Ok(private_key) => private_key
            };
            // let private = private_options.acquire().unwrap();

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

            // TODO: The output will be a dictionary of the certificate's properties (friendly name, private key, public key, etc.)
            // let output_dict: Vec<(&str, PyObject)> = vec![
            //     ("Friendly Name", match friendly_name.into_pyobject(py){
            //         Ok(obj) => obj,
            //         Err(_) => "".to_string().into_pyobject(py).unwrap()
            //     }),
            // ];
            // let dict = output_dict.into_py_dict(py);

            // return Ok("Found a certificate.".to_string());
            
            return Ok(output_dict);
        }
    }

    // Err(PyRuntimeError::new_err("Invalid State Reached."))
}
