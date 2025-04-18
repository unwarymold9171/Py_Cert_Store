import py_cert_store
# from cryptography import x509

# key_usage_oid = x509.OID_KEY_USAGE
# key_usage_oid.dotted_string

# TODO: extention_oid needs to be derived from x509.OID_KEY_USAGE
# To handel this, I may need to add a hashmap matching the Cryptography OID to the Windows OIDs in the module

rust_cert = py_cert_store.get_win_cert(return_as_dict=True, verbose=False)

print(rust_cert)


from wincert import WinCerts

with WinCerts() as certs:
    dotnet_cert = certs.get_cert(return_as_dict=True, verbose=False)


print("Rust FriendlyName: ", rust_cert["FriendlyName"])
print(".NET FriendlyName: ", dotnet_cert["FriendlyName"])

print("Rust Name: ", rust_cert["Name"])
print(".NET Name: ", dotnet_cert["Name"])

print("Rust IssuerName: ", rust_cert["IssuerName"])
print(".NET IssuerName: ", dotnet_cert["IssuerName"])

print("Rust EffectiveDateString: ", rust_cert["EffectiveDateString"])
print(".NET EffectiveDateString: ", dotnet_cert["EffectiveDateString"])

print("Rust ExpirationDateString: ", rust_cert["ExpirationDateString"])
print(".NET ExpirationDateString: ", dotnet_cert["ExpirationDateString"])


print("Certificates are equal: ", rust_cert["cert"] == dotnet_cert["cert"])

pass_fail = {
    "FriendlyName": rust_cert["FriendlyName"] == dotnet_cert["FriendlyName"],
    "Name": rust_cert["Name"] == dotnet_cert["Name"],
    "IssuerName": rust_cert["IssuerName"] == dotnet_cert["IssuerName"],
    "EffectiveDateString": rust_cert["EffectiveDateString"] == dotnet_cert["EffectiveDateString"],
    "ExpirationDateString": rust_cert["ExpirationDateString"] == dotnet_cert["ExpirationDateString"],
    "cert": rust_cert["cert"] == dotnet_cert["cert"],
}

print("Pass/Fail: ", pass_fail)
print("All tests pass: ", all(pass_fail.values()))
