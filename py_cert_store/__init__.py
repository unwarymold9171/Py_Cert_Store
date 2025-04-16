# Copyright 2025 Niky H. (Unwarymold9171)
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

from .__about__ import __copyright__, __version__, __author__
from .py_cert_store import *

__all__ = {
    "__author__",
    "__copyright__",
    "__version__",
}

def get_win_cert(store:str="My", extension_oid:int=None, extension_value:str=None, as_dict:bool=False) -> bytes | dict[str, str|bytes]:
    """
    Gets a user's certificate from the Windows certificate store.

    :param store: The name of the certificate store to search in.
        - Default is "My" (Personal store).
    :param extension_oid: The object ID of the extension to search for.
        - This number can be found with the `Cryptography` python package.
    :param extension_value: The value of the extension to search for.
        - This is the value of the extension to search for.
    :param as_dict: If True, return the certificate as a dictionary.
        - Default is False.
    
    :return: The certificate found as `bytes` or a dictionary with the certificate and its properties.
    """
    certificate = find_windows_cert_by_extension(store=store, extension_oid=extension_oid, extension_value=extension_value)

    # TODO: Check that this is the style that replicates the original finction this will be replacing
    console_string = f"Certificate: {certificate['FriendlyName']}\n" \
        f"{certificate['Name']}\n" \
        f"Validity: {certificate['EffectiveDateString']} - {certificate['ExpirationDateString']}"

    print(console_string)

    if as_dict:
        return certificate
    return certificate['cert']
