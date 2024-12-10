# Using provided Certs

When prompted with a password leave the field blank.

Re-generating the .p12 from the other provided cert files:
- `openssl pkcs12 -export -out client-id.p12 -inkey key.pem -in certificate.pem -name "Rust Test Cert"`

## Windows

1. Double click on the `client-id.p12` file
2. Install for the current user
3. Advance to the `Private Key Protection` page of the installer (This page will have a password box)
  1. Leave the Password blank
  2. Click the `Mark this key as exportable` check box
4. Advance all the way to the `Completing the Certificate Import Wizard` page and click `Finish`
