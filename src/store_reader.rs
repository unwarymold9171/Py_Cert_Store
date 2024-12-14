#[deny(clippy::unwrap_used)]
#[deny(clippy::expect_used)]
#[deny(clippy::panic)]

use pyo3::prelude::*;
use pyo3::exceptions::{PyOSError, PyRuntimeError};
// use schannel::cert_store::CertStore; // TODO: Fully replace
// use schannel::cert_context::{ValidUses, PrivateKey}; // TODO: Fully replace

use crate::windows_store::cert_store::CertStore;
use crate::windows_store::cert_context::CertContext;


#[pyfunction]
#[pyo3(signature = (key_usage, store="My"))]
pub fn get_win_cert(key_usage:&str, store:&str) -> PyResult<String>  {
    if !cfg!(windows){
        return Err(PyOSError::new_err("The `get_win_cert` function can only called from a Windows computer.")); // TODO
    }
    println!("Windows");

    let certs = match CertStore::open_current_user(store){
        Ok(certs) => certs,
        Err(_) => {
            return Err(PyRuntimeError::new_err("Could not open the certificate store."));
        }
    };

    #[allow(unused_mut)] // TODO: Remove
    let mut targeted_cert: Option<CertContext> = None;

    #[allow(unused_labels)] // TODO: Remove
    'outer: for cert in certs.certs() {
        let friendly_name = match cert.friendly_name() {
            Ok(name) => name,
            Err(_) => {
                println!("Found cert with no Friendly Name. Skipping...");
                continue;
                // TODO: Give a generic Friendly Name rather than skip the file
            }
        };

        if !cert.is_time_valid().unwrap() {
            println!("Skipped {}, expired. Skipping...", friendly_name);
            continue;
        }

        // This is not the step I wish to take here,
        // I want to read all extented fields

        // Based on documentation of schannel and rustls-cng
        // I may have to rewrite/add to their existing features before I can get the information I need

        // let usage = cert.valid_uses().unwrap(); // TODO: Error handling (clippy is set to deny unwrap)

        // match usage {
        //     ValidUses::All => {
        //         println!("Found cert with all usages. \n\t🔑: {}", friendly_name);
        //         targeted_cert = Some(cert);
        //         break 'outer;
        //     }
        //     ValidUses::Oids(use_list) => {
        //         println!("Limited Usage");
        //         for u in use_list {
        //             if u.contains(key_usage) {
        //                 println!("Found with uses case.\n\t{}", friendly_name);
        //                 targeted_cert = Some(cert);
        //                 break 'outer;
        //             }
        //         }
        //     }
        // }

    }

    match targeted_cert {
        None => {
            return Err(PyRuntimeError::new_err("No Valid "))
        },
        #[allow(unused_variables)] // TODO: Remove
        Some(cert) => {
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

    //         return Ok(key_usage.to_string());
        }
    }
    Ok(key_usage.to_string())

}
