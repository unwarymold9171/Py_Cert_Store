import py_cert_store
from cryptography import x509

# print(py_cert_store.__all__)
key_usage_oid = x509.OID_KEY_USAGE

# TODO: extention_oid needs to be derived from x509.OID_KEY_USAGE

print(py_cert_store.find_windows_cert_by_extention(extention_value="Digital Signature"))
