# Copyright 2025 Niky H. (Unwarymold9171)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Dict, Union, List


def find_windows_cert_by_extension(store:str="My", user:str="CurrentUser", extension_oid:str=None, extension_value:str=None) -> List[Dict[str, Union[str,bytes]]]:
    """
    Find a certificate in the Windows certificate store by its extension.

    :param store: The name of the certificate store to search in.
        - example: "My", "Root", "CA", etc.
    :param user: The user to get the certificate from.
        - example: "CurrentUser", "LocalMachine".
    :param extension_oID: The object ID string of the extension to search for.
        - It is recommended to use the dotted string from the python `cryptography` package.
            - example: `x509.OID_KEY_USAGE.dotted_string`.
    :param extension_value: The value of the extension to search for.

    :return: The return is a list of dictionaries with the following keys:
        - "cert": The certificate bytes.
        - "FriendlyName": The friendly name of the certificate.
        - "Name": The name of the certificate.
        - "IssuerName": The issuer name of the certificate.
        - "EffectiveDateString": The effective date of the certificate as a string.
        - "ExpirationDateString": The expiration date of the certificate as a string.
    """

def find_windows_cert_all(store:str="My", user:str="CurrentUser") -> List[Dict[str, Union[str,bytes]]]:
    """
    Find all time valid certificates in the Windows certificate store.

    :param store: The name of the certificate store to search in.
        - example: "My", "Root", "CA", etc.
    :param user: The user to get the certificate from.
        - example: "CurrentUser", "LocalMachine".

    :return: The return is a list of dictionaries with the following keys:
        - "cert": The certificate bytes.
        - "FriendlyName": The friendly name of the certificate.
        - "Name": The name of the certificate.
        - "IssuerName": The issuer name of the certificate.
        - "EffectiveDateString": The effective date of the certificate as a string.
        - "ExpirationDateString": The expiration date of the certificate as a string.
    """

class CertNotExportable(Exception):
    """
    Raised when the certificate is not exportable.
    """

class CertNotFound(Exception):
    """
    Raised when there is no certificate found with the given parameters.
    """
