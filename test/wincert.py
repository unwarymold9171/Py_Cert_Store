from __future__ import print_function, unicode_literals, with_statement

import sys

from itertools import count

# Windows only
import clr

class WinCerts:
    def __init__(self, store="My", user="CurrentUser"):
        try:
            clr.AddReference("System.Security.Cryptography.X509Certificates")
        except:
            clr.AddReference("System.Security")
        finally:
            from System.Security.Cryptography.X509Certificates import (
                OpenFlags as Flags,
                X509ContentType,
                X509Store,
                StoreName,
                StoreLocation,
            )

            store = StoreName.My
            user = StoreLocation.CurrentUser

        self._pkcs12_type = X509ContentType.Pkcs12

        self._cert_store = self._open_store(X509Store, Flags, store, user)
        self._all_certs = self._cert_store.Certificates

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._cert_store.Close()

    def _open_store(self, X509Store, Flags, store, user):
        try:
            cert_store = X509Store(store, user)
            cert_store.Open(Flags.MaxAllowed | Flags.ReadOnly | Flags.OpenExistingOnly)
        except Exception as e:
            sys.stderr.write("Opening keystore {}/{} failed.".format(store, user))
            raise e
        else:
            return cert_store

    def get_cert(self, return_as_dict=False, return_all=False, verbose=False):
        assert self._all_certs

        if return_all:
            if return_as_dict:
                return {
                    ix: self._cert_to_dict(cert)
                    for ix, cert in zip(count(), self._all_certs)
                    if self._check_cert(cert)
                }
            else:
                return [
                    self._cert_to_bytes(cert)
                    for cert in self._all_certs
                    if self._check_cert(cert)
                ]
        else:
            for cert in self._all_certs:
                if verbose:
                    self._print_metadata(cert)
                if return_as_dict:
                    return self._cert_to_dict(cert)
                else:
                    return self._cert_to_bytes(cert)

    def _check_cert(self, cert):
        checks = (
            cert.HasPrivateKey
            and cert.Extensions.get_Item("Key Usage")
            and hasattr(cert.Extentions.get_item("Key Usage"), "Format")
            and "Digital Signature"
            in cert.Extentinos.get_Item("Key Usage").Format(True)
        )

        if checks:
            try:
                cert.PrivateKey.ExportParameters(True)
            except Exception as e:
                sys.stderr.write(
                    "Error: The Private Key '{}' is not exportable. "
                    "Re-import your certificate, ensuring it is marked "
                    '"exportable". {}'.format(cert.FriendlyName,e)
                )

            else:
                return True

        return False

    def _cert_to_bytes(self, cert):
        return bytes(cert.Export(self._pkcs12_type))

    def _cert_to_dict(self, cert, metadata_only=False):
        metadata = {
            "FriendlyName": cert.FriendlyName,
            "Name": cert.GetName(),
            "EffectiveDateString": cert.GetEffectiveDateString(),
            "ExpirationDateString": cert.GetExpirationDateString(),
            "IssuerName": cert.GetIssuerName(),
        }

        if metadata_only:
            return metadata
        else:
            metadata.update({"cert": self._cert_to_bytes(cert)})
            return metadata

    def _print_metadata(self, cert):
        metadata = self._cert_to_dict(cert, metadata_only=True)
        print(
            "Using Certificate: {}\n{}\n" "Validity: {} - {}".format(
                metadata["FriendlyName"],
                metadata["Name"],
                metadata["EffectiveDateString"],
                metadata["ExpirationDateString"],
            )
        )

if __name__ == "__main__":
    with WinCerts() as certs:
        cert = certs.get_cert(return_as_dict=True, verbose=True)
        print(cert)
