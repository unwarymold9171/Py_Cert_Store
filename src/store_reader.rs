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

use std::collections::HashMap;
use pyo3::prelude::*; // TODO: properly import this module
use pyo3::exceptions::{PyOSError, PyRuntimeError};
use pyo3::types::{PyString, PyBytes};
use windows_sys::Win32::Security::Cryptography;

use crate::windows_store::cert_store::CertStore;
use crate::windows_store::cert_context::CertContext;
use crate::exceptions::CertNotExportable;


#[pyfunction]
#[pyo3(signature = (store="My", extension_oid=None, extension_value=None))]
/// Find a certificate in the Windows Certificate Store by its extension
#[allow(unused_variables)] // TODO: The extension OID and value are not used yet
pub fn find_windows_cert_by_extension(store:&str, extension_oid:Option<u8>, extension_value:Option<&str>) -> PyResult<HashMap<String, PyObject>> {
    // TODO: Change the output of this function to a vector of dictionaries. Since this currently only returns the first cert found that matches the criteria.
    // The only reason there could be multiple certs (in the case this is designed for) would be if the user has been issued new certs, and the old certs are still valid.
    // While this should not cause issues, it may be worth considering to return all certs that match the criteria.
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
        //         // TODO: Move the match statement below to here
        //     },
        //     None => {
        //         if !extension_value.is_none() {
        //             // No extension OID is provided, assume that the user only wants to find a time valid cert
        //             targeted_cert = Some(cert);
        //         }
        //     }
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

    let mut output_dict: HashMap<String, PyObject> = HashMap::new();

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
            output_dict.insert("FriendlyName".to_string(), create_python_string(&friendly_name));

            let subject = cert.name().unwrap_or("".to_string());
            output_dict.insert("Name".to_string(), create_python_string(&subject));

            let issuer = cert.issuer().unwrap_or("".to_string());
            output_dict.insert("IssuerName".to_string(), create_python_string(&issuer));

            let valid_from = cert.valid_from().unwrap_or("ERROR".to_string());
            output_dict.insert("EffectiveDateString".to_string(), create_python_string(&valid_from));

            let valid_to = cert.valid_to().unwrap_or("ERROR".to_string());
            output_dict.insert("ExpirationDateString".to_string(), create_python_string(&valid_to));

            let private_options = cert.private_key().map_err(|_| {
                PyRuntimeError::new_err("Could not get the private key.")
            })?;
            // TODO: Check if this is the correct output value.
            // I am unable to test this without pulling code from another project that returns the private key.
            //
            // Milestone #1 - Get an initial testable version of the code working (Complete)
            // 
            // This appears to be returning a diffrent value each time it is called, this should not be the case.
            output_dict.insert("cert".to_string(), create_python_bytes(&private_options.as_slice()));

            return Ok(output_dict);
        }
    }

    // Err(PyRuntimeError::new_err("Invalid state reached."))

}

/// Helper function to create a Python string from a Rust string
fn create_python_string(value: &str) -> PyObject {
    Python::with_gil(|py| {
        PyString::new(py, value).into()
    })
}

/// Helper function to create a Python bytes object from a Rust byte slice
fn create_python_bytes(value: &[u8]) -> PyObject {
    Python::with_gil(|py| {
        PyBytes::new(py, value).into()
    })
}
