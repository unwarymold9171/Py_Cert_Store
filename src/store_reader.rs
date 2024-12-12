use pyo3::prelude::*;
use pyo3::exceptions::{PyOSError, PyRuntimeError};
use schannel::cert_store::CertStore;
use schannel::cert_context::{ValidUses, PrivateKey};


#[pyfunction]
#[pyo3(signature = (key_usage, store="My"))]
pub fn get_win_cert(key_usage:&str, store:&str) -> PyResult<String>  {
    if !cfg!(windows){
        return Err(PyOSError::new_err("The `get_win_cert` function can only called from a Windows computer.")); // TODO
    }
    println!("Windows");

    let certs: CertStore = CertStore::open_current_user(store).unwrap();

    let mut targeted_cert: Option<_> = None;

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

        let usage: ValidUses = cert.valid_uses().unwrap();

        match usage {
            ValidUses::All => {
                println!("Found cert with all usages. \n\t🔑: {}", friendly_name);
                targeted_cert = Some(cert);
                break 'outer;
            }
            ValidUses::Oids(use_list) => {
                println!("Limited Usage");
                for u in use_list {
                    if u.contains(key_usage) {
                        println!("Found with uses case.\n\t{}", friendly_name);
                        targeted_cert = Some(cert);
                        break 'outer;
                    }
                }
            }
        }

    }

    match targeted_cert {
        None => {
            return Err(PyRuntimeError::new_err("No Valid "))
        },
        Some(cert) => {
            // TODO
            let private_options = cert.private_key();
            let private = private_options.acquire().unwrap();

            match private {
                PrivateKey::CryptProv(_) => {
                    println!("CryptKey");
                    // TODO: I believe this is an error state here
                },
                PrivateKey::NcryptKey(key) => {
                    println!("NcryptKey");
                    // TODO: This is what the sample is
                }
            }

            return Ok(key_usage.to_string());
        }
    }

}
