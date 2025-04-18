import py_cert_store
# from cryptography import x509

# key_usage_oid = x509.OID_KEY_USAGE
# key_usage_oid.dotted_string

# TODO: extention_oid needs to be derived from x509.OID_KEY_USAGE
# To handel this, I may need to add a hashmap matching the Cryptography OID to the Windows OIDs in the module

certificate = py_cert_store.get_win_cert(return_as_dict=True, verbose=False)

print(certificate)



from wincert import WinCerts

with WinCerts() as certs:
    cert = certs.get_cert(return_as_dict=True, verbose=False)


print("Rust FriendlyName: ", certificate["FriendlyName"])
print(".NET FriendlyName: ", cert["FriendlyName"])
print("Rust Name: ", certificate["Name"])
print(".NET Name: ", cert["Name"])
print("Rust EffectiveDateString: ", certificate["EffectiveDateString"])
print(".NET EffectiveDateString: ", cert["EffectiveDateString"])
print("Rust ExpirationDateString: ", certificate["ExpirationDateString"])
print(".NET ExpirationDateString: ", cert["ExpirationDateString"])
# print("Rust Certificate: ", certificate["cert"])
# print(".NET Certificate: ", cert["cert"])

print("Certificates are equal: ", certificate["cert"] == cert["cert"])
