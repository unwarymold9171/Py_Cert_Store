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

use crate::windows_store::cert_store::CertStore;
use crate::windows_store::cert_context::CertContext;
use crate::exceptions::{CertNotExportable, CertNotFound};


#[pyfunction]
#[pyo3(signature = (store="My", user="CurrentUser", extension_oid=None, extension_value=None))]
/// Find a certificate in the Windows Certificate Store by its extension OID and value.
pub fn find_windows_cert_by_extension(store:&str, user:&str, extension_oid:Option<&str>, extension_value:Option<&str>) -> PyResult<Vec<HashMap<String, PyObject>>> {
    if !cfg!(windows) {
        return Err(PyOSError::new_err("The \"find_windows_cert_by_extension\" function can only be called from a Windows computer."));
    }

    let certs = match get_certs_from_store(store, user) {
        Ok(certs) => certs,
        Err(err) => {
            return Err(err);
        }
    };

    let mut valid_certificates: Vec<CertContext> = Vec::new();

    for cert in certs.certs() {

        match cert.is_time_valid() {
            Ok(valid) => {
                if !valid {
                    // The certificate is not time valid, so close the certificate and continue to the next one.
                    cert.close();
                    continue;
                }
            },
            Err(_) => {
                // There was an error checking the time validity, so close the certificate and continue to the next one.
                cert.close();
                continue
            }
        }

        match extension_oid {
            Some(oid) => {
                match cert.has_extension_with_property(oid.as_ptr() as *const _, extension_value) { // TODO: Alter this function to take other parameters
                    Ok(has) => {
                        if has {
                            valid_certificates.push(cert);
                        } else {
                            // The certificate does not have the requested extension, so close it and continue to the next one.
                            cert.close();
                        }
                        continue;
                    },
                    Err(_) => {
                        // There was an error checking the extension, so close the certificate and continue to the next one.
                        cert.close();
                        continue;
                    }
                };
            },
            None => {
                if !extension_value.is_none() {
                    // No extension OID is provided, assume that only cares about the time validity of the certificate.
                    valid_certificates.push(cert);
                }
            }
        };
    }

    if valid_certificates.len() == 0 {
        return Err(CertNotFound::new_err("No valid certificates found."));
    }

    let mut output_dicts: Vec<HashMap<String, PyObject>> = Vec::new();

    for cert in valid_certificates {
        let output_dict = build_dict_from_cert(&cert).unwrap_or_default();
        if !output_dict.is_empty() {
            output_dicts.push(output_dict);
        }
        cert.close();
    };

    if output_dicts.len() == 0 {
        return Err(CertNotExportable::new_err("No Exportable certificates found."));
    }

    return Ok(output_dicts);
}

#[pyfunction]
#[pyo3(signature = (store="My", user="CurrentUser"))]
pub fn find_windows_cert_all(store:&str, user:&str) -> PyResult<Vec<HashMap<String, PyObject>>> {
    if !cfg!(windows) {
        return Err(PyOSError::new_err("The \"find_windows_cert_all\" function can only be called from a Windows computer."));
    }

    let certs = match get_certs_from_store(store, user) {
        Ok(certs) => certs,
        Err(err) => {
            return Err(err);
        }
    };

    let mut valid_certificates: Vec<CertContext> = Vec::new();

    for cert in certs.certs() {

        match cert.is_time_valid() {
            Ok(valid) => {
                if !valid {
                    // The certificate is not time valid, so close the certificate and continue to the next one.
                    cert.close();
                    continue;
                }
            },
            Err(_) => {
                // There was an error checking the time validity, so close the certificate and continue to the next one.
                cert.close();
                continue
            }
        }
        valid_certificates.push(cert);
    }

    if valid_certificates.len() == 0 {
        return Err(CertNotFound::new_err("No valid certificates found."));
    }

    let mut output_dicts: Vec<HashMap<String, PyObject>> = Vec::new();

    for cert in valid_certificates {
        let output_dict = build_dict_from_cert(&cert).unwrap_or_default();
        if !output_dict.is_empty() {
            output_dicts.push(output_dict);
        }
        cert.close();
    };

    if output_dicts.len() == 0 {
        return Err(CertNotExportable::new_err("No Exportable certificates found."));
    }

    return Ok(output_dicts);
}

fn get_certs_from_store(store:&str, user:&str) -> Result<CertStore, PyErr>{
    if !cfg!(windows) {
        panic!("The \"get_certs_from_store\" function can only be called from a Windows computer.");
    }

    let user = user.to_lowercase();
    let certs = match user.as_str() {
        "currentuser" => {
            CertStore::open_current_user(store).map_err(|_| {
                PyRuntimeError::new_err("Could not open the certificate store.")
            })
        },
        "localmachine" => {
            CertStore::open_local_machine(store).map_err(|_| {
                PyRuntimeError::new_err("Could not open the certificate store.")
            })
        },
        _ => {
            return Err(PyOSError::new_err("Invalid user parameter. Use 'CurrentUser' or 'LocalMachine'."));
        },
    };

    let certs = match certs {
        Ok(certs) => certs,
        Err(_) => {
            return Err(PyRuntimeError::new_err("Could not open the certificate store."));
        }
    };

    return Ok(certs)
}

fn build_dict_from_cert(cert: &CertContext) -> PyResult<HashMap<String, PyObject>> {
    let mut dict = HashMap::new();

    match cert.is_exportable() {
        Ok(exportable) => {
            if !exportable {
                return Err(CertNotExportable::new_err("The certificate is not exportable."));
            }
        },
        Err(_) => {
            return Err(PyRuntimeError::new_err("Unable to determine if the certificate is exportable."));
        }
    }

    let friendly_name = cert.friendly_name().unwrap_or("".to_string());
    dict.insert("FriendlyName".to_string(), create_python_string(&friendly_name));

    let subject = cert.name().unwrap_or("".to_string());
    dict.insert("Name".to_string(), create_python_string(&subject));

    let issuer = cert.issuer().unwrap_or("".to_string());
    dict.insert("IssuerName".to_string(), create_python_string(&issuer));

    let valid_from = cert.valid_from().unwrap_or("".to_string());
    dict.insert("EffectiveDateString".to_string(), create_python_string(&valid_from));

    let valid_to = cert.valid_to().unwrap_or("".to_string());
    dict.insert("ExpirationDateString".to_string(), create_python_string(&valid_to));

    let private_options = cert.private_key().map_err(|_| {
        PyRuntimeError::new_err("Could not get the private key.")
    })?;

    // NOTE: The private key may be correct, but until this is tested on a live system, I am guessing that this is the expected output.
    dict.insert("cert".to_string(), create_python_bytes(&private_options.as_slice()));

    Ok(dict)
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
