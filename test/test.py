import py_cert_store

# Case 1: This is the original design of this module.
# This method was integrated into case 2, but is here to ensure that there are no issues caused by mutiple calls to the underlying library.
from cryptography import x509

key_usage_oid = x509.OID_KEY_USAGE

alternitive_cert_export = py_cert_store.find_windows_cert_by_extension(
    store="My",
    extension_oid=key_usage_oid.dotted_string,
    extension_value="Digital Signature"
)

print(f"Using Certificate: {alternitive_cert_export[0]['FriendlyName']}")
print(f"{alternitive_cert_export[0]['Name']}")
print(f"Validity: {alternitive_cert_export[0]['EffectiveDateString']} - {alternitive_cert_export[0]['ExpirationDateString']}")
print("")

# Case 2: This is the expected use case for this module.
# This call is the same as above, but simplified to use less input parameters.
rust_cert = py_cert_store.get_win_cert(return_as_dict=True, verbose=False)

# print(rust_cert)
# print("")


# Case 3: This is the .NET base line that this module is trying to replace.
# This method uses pythonnet to extract the certificate from the Windows certificate store using the .NET library functions.
# The output for this case should be treated as the truth for this module to be compared against.
from wincert import WinCerts

with WinCerts() as certs:
    dotnet_cert = certs.get_cert(return_as_dict=True, verbose=False)


# Varification:
# Compare Case 2 and Case 3 to ensure that the two libraries are returning the same values.

pass_fail = {
    "FriendlyName": rust_cert["FriendlyName"] == dotnet_cert["FriendlyName"],
    "Name": rust_cert["Name"] == dotnet_cert["Name"],
    "IssuerName": rust_cert["IssuerName"] == dotnet_cert["IssuerName"],
    "EffectiveDateString": rust_cert["EffectiveDateString"] == dotnet_cert["EffectiveDateString"],
    "ExpirationDateString": rust_cert["ExpirationDateString"] == dotnet_cert["ExpirationDateString"],
    # "cert": rust_cert["cert"] == dotnet_cert["cert"],
}

# Print the results if a particular element failed to match.
# This way the console output is not cluttered with information that is not needed.

if not pass_fail["FriendlyName"]:
    print("Rust FriendlyName: ", rust_cert["FriendlyName"])
    print(".NET FriendlyName: ", dotnet_cert["FriendlyName"])

if not pass_fail["Name"]:
    print("Rust Name: ", rust_cert["Name"])
    print(".NET Name: ", dotnet_cert["Name"])

if not pass_fail["IssuerName"]:
    print("Rust IssuerName: ", rust_cert["IssuerName"])
    print(".NET IssuerName: ", dotnet_cert["IssuerName"])

if not pass_fail["EffectiveDateString"]:
    print("Rust EffectiveDateString: ", rust_cert["EffectiveDateString"])
    print(".NET EffectiveDateString: ", dotnet_cert["EffectiveDateString"])

if not pass_fail["ExpirationDateString"]:
    print("Rust ExpirationDateString: ", rust_cert["ExpirationDateString"])
    print(".NET ExpirationDateString: ", dotnet_cert["ExpirationDateString"])

# Cert bytes strings cannot be compared directly since each library will return a different string each time they are run.
# TODO: Find a way to compare the private key bytes to see if they are the same.
"""
if not pass_fail["cert"]:
    print("")
    print("Rust cert: ", rust_cert["cert"])
    print("")
    print(".NET cert: ", dotnet_cert["cert"])
    print("")

print("Certificates are equal: ", rust_cert["cert"] == dotnet_cert["cert"])
print("")
"""

print("Pass/Fail: ", pass_fail)
print("All tests pass: ", all(pass_fail.values()))

# TODO: Future convert this into a proper test case using pytest or similar.
# As a test case, it may have to run a powershell script to create a certificate it can use to test against, when running on a clean system. (like a CI/CD pipeline)
