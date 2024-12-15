#![cfg(windows)]

use pyo3::prelude::*;

pub mod store_reader;
pub mod windows_store;

/// Formats the sum of two numbers as string.
// #[pyfunction]
// fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
//     Ok((a + b).to_string())
// }

/// A Python module implemented in Rust.
#[pymodule]
fn py_cert_store(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_function(wrap_pyfunction!(store_reader::find_windows_cert_by_extention, m)?)?;
    Ok(())
}
