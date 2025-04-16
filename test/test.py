import py_cert_store
from cryptography import x509

key_usage_oid = x509.OID_KEY_USAGE
# key_usage_oid.dotted_string

# TODO: extention_oid needs to be derived from x509.OID_KEY_USAGE
# To handel this, I may need to add a hashmap matching the Cryptography OID to the Windows OIDs in the module

print(py_cert_store.get_win_cert(extension_value="Digital Signature"))
