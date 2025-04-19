[![CI](https://github.com/unwarymold9171/Py_Cert_Store/actions/workflows/CI.yml/badge.svg)](https://github.com/unwarymold9171/Py_Cert_Store/actions/workflows/CI.yml)
![PyPI](https://img.shields.io/pypi/v/py_cert_store?link=https%3A%2F%2Fpypi.org%2Fproject%2Fpy-cert-store%2F)
<!-- ![PyPI - Downloads](https://img.shields.io/pypi/dm/py_cert_store) -->
<!-- The downloads badge seems to not be working at this time -->

# Python Certificate Store

The Python Certificate Store (Py_Cert_Store) is a module designed with the intention of interacting with the windows certificate store.

The initial design of this module is to find a certificate meeting a set of basic criteria (Not expired, contains an extension, and is exportable).

## Python Implementation

This code is designed to return a certificate that can be utilized when connecting with the python requests library.

```python
from py_cert_store import get_win_cert
from requests import Session
from requests_pkcs12 import Pkcs12Adapter

certificate = get_win_cert()

with Session() as s:
    s.mount('https://example.com', Pkcs12Adapter(pkcs12_data=certificate))
    r = s.get('https://example.com/test')
```

For further selection of a certificate from the windows certificate store 

```python
from py_cert_store import find_windows_cert_by_extension
from cryptography import x509

valid_certificates = find_windows_cert_by_extension(
    store="My", user:str="CurrentUser",
    extension_oid=x509.OID_KEY_USAGE.dotted_string,
    extension_value="Digital Signature"
)

certificate_with_metadata = valid_certificates[0]

print(f"Using Certificate: {certificate_with_metadata['FriendlyName']}")
print(f"{certificate_with_metadata['Name']}")
print(f"Validity: {certificate_with_metadata['EffectiveDateString']} - {certificate_with_metadata['ExpirationDateString']}")

certificate = certificate_with_metadata["cert"]

...
```
<!-- ```python
``` -->

## Installing

This library is available as [PyPI package](https://pypi.org/project/py-cert-store):

```
pip install py_cert_store
```

Alternatively, you can retrieve the latest development version via Git: (Note: Rust must be installed to run the development branch)

```
git clone https://github.com/unwarymold9171/Py_Cert_Store.git
```
