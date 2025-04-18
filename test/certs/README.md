# Using provided Certs

The certificates in this folder are test files to help test and debug this module, while providing a consistant output each time.

## Notice

Currently the files in this folder appear to be broken. Use the PowerShell command found in the [Generating a self signed certificate](#generating-a-self-signed-certificate) section.

## Generating a self signed certificate

In Windows PowerShell run the following command:

```powershell
New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My `
    -Subject "CN=Test Exportable Cert, O=Py_Cert_Store Examples, C=US" `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -Type DocumentEncryptionCert `
    -FriendlyName "Example Exportable Cert"
```

This command will generate a new certificate that will always meet the standard use case of this module.

<!-- When prompted for the password enter: `pass1234`.

Re-generating the .p12 from the other provided cert files:
- Regenerate the certiticate .pem:
  - `openssl req -x509 -new -key private_key.pem -days 365 -out certificate.crt -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment, cRLSign, keyCertSign" -addext "extendedKeyUsage = serverAuth, clientAuth"`
- Generate the .p12 files:
  - `openssl pkcs12 -export -out certificate.p12 -inkey private_key.pem -in certificate.crt -name "Rust Test Cert" -passout pass:pass1234`

## Windows: Certificate Import

1. Double click on a `.p12` file
2. Install for the current user
3. Advance to the `Private Key Protection` page of the installer (This page will have a password box)
  1. Enter in the certificate's pass word (when using the `.p12`s from this repo the password is set to: `pass1234`)
  2. Click the `Mark this key as exportable` check box
4. Advance all the way to the `Completing the Certificate Import Wizard` page and click `Finish`

## Windows: PowerShell

1. Open Powershell
2. Save the password as an environment variable: `$password = ConvertTo-SecureString -String "pass1234" -AsPlainText -Force`
3. Enter the import command: `Import-PfxCertificate -FilePath "C:\path\to\certificate.p12" -CertStoreLocation Cert:\CurrentUser\My -Exportable -Password $password`
  1. It is recommend to launch power shell from the folder the `.p12` file is in to simplify the File Path paramater to `"./certificate.p12"` -->
