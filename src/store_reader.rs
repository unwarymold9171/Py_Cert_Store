use pyo3::prelude::*;
use schannel::cert_store::CertStore;
use schannel::cert_context::CertContext;

#[pyfunction]
pub fn get_win_cert(which:&str, cert_name_frag:&str) -> PyResult<String>  {
    if !cfg!(windows){
        panic!(
            "The get_win_cert function can only be called from a Windows computer."
        );
        // println!("Not Windows");
        // return Ok("".to_string());
    }
    println!("Windows");

    let certs: CertStore = CertStore::open_current_user(which).unwrap();

    let mut targeted_cert: Option<CertContext> = None;

    for cert in certs.certs() {
        let name: String = cert.friendly_name().unwrap();
        println!("{}", name);
        if name.contains(cert_name_frag) {
            println!("Found");
            // targeted_cert = cert;
        }
    }

    // println!("{}", cert);

    return Ok(cert_name_frag.to_string());
}
