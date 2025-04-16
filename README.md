[![CI](https://github.com/unwarymold9171/Py_Cert_Store/actions/workflows/CI.yml/badge.svg)](https://github.com/unwarymold9171/Py_Cert_Store/actions/workflows/CI.yml)
![PyPI](https://img.shields.io/pypi/v/py_cert_store?link=https%3A%2F%2Fpypi.org%2Fproject%2Fpy-cert-store%2F)
<!-- ![PyPI - Downloads](https://img.shields.io/pypi/dm/py_cert_store) -->
<!-- The downloads badge seems to not be working at this time -->

# Python Certificate Store

The Python Certificate Store (Py_Cert_Store) is a module designed with the intention of interacting with the windows certificate store.

The initial design of this module is to find a certificate meeting a set of basic criteria (Not expired, contains an extension, and is exportable).

# Note:

This project is a Work in Progress and changes will be made

## Python Implementation (WIP)

This code is designed to return information about a discovered certificate; this information can be used to write a new SSL connection.

```python
import py_cert_store
from cryptography import x509 # This feature is not working currently # Optional, but highly recomended

key_usage_oid = x509.OID_KEY_USAGE

certificate = py_cert_store.find_windows_cert_by_extension(
    store="MY",
    extension_oid=key_usage_oid.dotted_string,
    extension_value="Digital Signature"
)
```

WIP: How to use the certificate found by the module with a new ssl context
