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

from __future__ import annotations
from typing import Union, Dict, List

from .__about__ import __copyright__, __version__, __author__
from .py_cert_store import *

__all__ = {
    "__author__",
    "__copyright__",
    "__version__",
}

def get_win_cert(
        store:str="My", user:str="CurrentUser",
        return_as_dict:bool=False, return_all:bool=False,
        verbose:bool=True
    ) -> Union[bytes, Dict[str, Union[str, bytes]], List[bytes], List[Dict[str, Union[str, bytes]]]]:
    # :param user: The user to get the certificate from. Default is "CurrentUser".
    """
    Gets a user's certificate from the Windows certificate store.

    :param store: The name of the certificate store to search in. Default is "My".
    :param return_as_dict: If True, returns the certificate(s) as a dictionary, and False returns the certificate bytes only.
    :param return_all: If True, returns all vlid certificates. Default is False.
    :param verbose: If True, prints information about the certificate discovered to the console.

    :return List, Dict, Bytes: The found certificate.
        - if return_all is True, a list will be returned based on return_as_dict's value.
        - If return_as_dict is True, returns a dictionary with additional metadata about the certificate.
        - If return_as_dict is False, returns the certificate bytes only.
    """
    from cryptography import x509 # There is no reason to import this in the overall module, since this is the only time the dependency is used.

    certificate_list = find_windows_cert_by_extension(store=store, user=user, extension_oid=x509.OID_KEY_USAGE.dotted_string, extension_value="Digital Signature")

    if return_all:
        if return_as_dict:
            return certificate_list
        return [cert['cert'] for cert in certificate_list]

    if verbose:
        print(f"Using Certificate: {certificate_list[0]['FriendlyName']}")
        print(f"{certificate_list[0]['Name']}")
        print(f"Validity: {certificate_list[0]['EffectiveDateString']} - {certificate_list[0]['ExpirationDateString']}")

    if return_as_dict:
        return certificate_list[0]
    return certificate_list[0]['cert']
