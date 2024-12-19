# Python Certificate Store

The Python Certificate Store (Py_Cert_Store) is a module designed with the intention of interacting with the windows certificate store.

The initial design of this module is to find a certificate meeting a set of basic criteria (Not expired, contains an extention, and is exportable).

# Note:

This project is a Work in Progress and changes will be made

## Python Implementation (WIP)

This code is designed to return information about a discovered certificate; this information can be used to write a new SSL connection.

```python
import py_cert_store
from cryptography import x509 # This feature is not working currently # Optional, but highly recomended

key_usage_oid = x509.OID_KEY_USAGE

certificate = py_cert_store.find_windows_cert_by_extention(store="MY", key_usage_oid=key_usage_oid.dotted_string, extention_value="Digital Signature")
```

WIP: How to use the certificate found by the module with a new ssl context
