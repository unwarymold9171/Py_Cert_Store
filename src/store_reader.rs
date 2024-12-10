use pyo3::prelude::*;
use pyo3::exceptions::{PyOSError, PyRuntimeError};
use schannel::cert_store::CertStore;
use schannel::cert_context::ValidUses;

#[pyfunction]
#[pyo3(signature = (key_usage, store="My"))]
pub fn get_win_cert(key_usage:&str, store:&str) -> PyResult<String>  {
    if !cfg!(windows){
        return Err(PyOSError::new_err("The `get_win_cert` function can only called from a Windows computer.")); // TODO
    }
    println!("Windows");

    let certs: CertStore = CertStore::open_current_user(store).unwrap();

    let mut targeted_cert: Option<_> = None;

    for cert in certs.certs() {
        let name: String = cert.friendly_name().unwrap(); // TODO: Handle and skip over Certs missing a "Friendly Name"
        println!("{}", name);
        if !cert.is_time_valid().unwrap() {
            println!("Skipped {}, expired", name);
            continue;
        }

        let usage: ValidUses = cert.valid_uses().unwrap();

        match usage {
            ValidUses::All => {
                println!("Found cert with all usages. \n\t{}", name);
                targeted_cert = Some(cert);
                break;
            }
            _ => {
                // for u in usage
                println!("Limited Usage");
                // TODO: scan through the usages for key_usage
                // usage;
            }
        }

    }

    match targeted_cert {
        None => {
            return Err(PyRuntimeError::new_err("No Valid "))
        },
        _ => {
            return Ok(key_usage.to_string());
        }
    }

}
