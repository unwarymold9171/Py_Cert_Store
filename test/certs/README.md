# Using provided Certs

When prompted with a password leave the field blank.

Re-generating the .p12 from the other provided cert files:
- `openssl req -x509 -sha256 -days 365 -key key.pem -in cert.cer -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment, cRLSign, keyCertSign" -addext "extendedKeyUsage = serverAuth, clientAuth" -out certificate2.pem`
- `openssl pkcs12 -export -out client-id-2.p12 -inkey key.pem -in certificate2.pem -name "Rust Test Cert 2"`

## Windows

1. Double click on the `client-id.p12` file
2. Install for the current user
3. Advance to the `Private Key Protection` page of the installer (This page will have a password box)
  1. Leave the Password blank
  2. Click the `Mark this key as exportable` check box
4. Advance all the way to the `Completing the Certificate Import Wizard` page and click `Finish`
