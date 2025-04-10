#![cfg(windows)]

use pyo3::prelude::*;
use pyo3::Python;

pub mod store_reader;
pub mod windows_store;
pub mod exceptions;

use exceptions::CertNotExportable;

/// A Python module implemented in Rust.
#[pymodule]
fn py_cert_store(py:Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_function(wrap_pyfunction!(store_reader::find_windows_cert_by_extension, m)?)?;
    m.add("CertNotExportable", py.get_type::<CertNotExportable>())?;
    Ok(())
}
