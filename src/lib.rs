// Copyright 2025 Niky H. (Unwarymold9171)
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
