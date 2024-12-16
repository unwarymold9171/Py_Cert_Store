use std::ptr;
use windows_sys::Win32::Security::Cryptography;

// use crate::windows_store::Inner;


pub struct CertExtention(*const Cryptography::CERT_EXTENSION);

// impl Clone for CertExtention {
//     fn clone(&self) -> CertExtention {
//         unsafe {
//             CertExtention(Cryptography::CertDuplicateCRLContext(self.0))
//         }
//     }
// }

inner_impl!(CertExtention, *const Cryptography::CERT_EXTENSION);

// NOTE: https://stackoverflow.com/questions/33129475/get-the-key-usage-from-certificate
// Idea, but not how to implement it
impl CertExtention {
    // TODO
}
