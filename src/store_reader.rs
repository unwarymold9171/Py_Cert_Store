#[deny(clippy::unwrap_used)]
#[deny(clippy::expect_used)]
#[deny(clippy::panic)]

use pyo3::prelude::*;
use pyo3::exceptions::{PyOSError, PyRuntimeError};
// use pyo3::types::IntoPyDict; // May need this?
use windows_sys::Win32::Security::Cryptography;

use crate::windows_store::cert_store::CertStore;
use crate::windows_store::cert_context::CertContext;
use crate::exceptions::CertNotExportable;


#[pyfunction]
#[pyo3(signature = (store="My", extention_oid=None, extention_value=None))]
/// Find a certificate in the Windows Certificate Store by its extention
#[allow(unused_variables)]
pub fn find_windows_cert_by_extention(store:&str, extention_oid:Option<u8>, extention_value:Option<&str>) -> PyResult<String>  {
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

            #[allow(unused_variables)] // TODO: Remove this line
            let friendly_name = match cert.friendly_name() {
                Ok(name) => name,
                Err(_) => {
                    "".to_string()
                }
            };

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

            // TODO: The output will be a dictionary of the certificate's properties (friendly name, private key, public key, etc.)
            // let output_dict: Vec<(&str, PyObject)> = vec![
            //     ("Friendly Name", match friendly_name.into_pyobject(py){
            //         Ok(obj) => obj,
            //         Err(_) => "".to_string().into_pyobject(py).unwrap()
            //     }),
            // ];
            // let dict = output_dict.into_py_dict(py);

            return Ok("Found a certificate.".to_string());
        }
    }
    // Ok("".to_string())

}
