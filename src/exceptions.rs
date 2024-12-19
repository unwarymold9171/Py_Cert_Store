use pyo3::create_exception;
use pyo3::exceptions::PyException;


create_exception!(py_cert_store, CertNotExportable, PyException);
// create_exception!(py_cert_store, CertStoreError, PyException);
