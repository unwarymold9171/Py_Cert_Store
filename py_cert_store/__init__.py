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
from typing import Union, Dict #, List

from .__about__ import __copyright__, __version__, __author__
from .py_cert_store import *

__all__ = {
    "__author__",
    "__copyright__",
    "__version__",
}

def get_win_cert(return_as_dict:bool=False, verbose=True) -> Union[bytes, Dict[str, Union[str, bytes]]]:
    # TODO: The other type of return, once it is implemented
        # List[bytes], List[Dict[str, Union[str, bytes]]]
    # TODO: Add aditional parameters to this function. For now it will only have the one parameter, and the others need to be added to the rust function.
        # user="CurrentUser", return_all=False
        # :param user: The user to get the certificate from. Default is "CurrentUser".
        # :param return_all: If True, returns all vlid certificates. Default is False.
    """
    Gets a user's certificate from the Windows certificate store.

    :param return_as_dict: If True, returns the certificate(s) as a dictionary, and False returns the certificate bytes only.
    :param verbose: If True, prints information about the certificate discovered to the console.

    :return: The certificate found as `bytes` or a dictionary with the certificate and its properties.
    """
    certificate = find_windows_cert_by_extension(extension_value="Digital Signature")

    # TODO: Check that this is the style that replicates the original finction this will be replacing
    console_string = f"Certificate: {certificate['FriendlyName']}\n" \
        f"{certificate['Name']}\n" \
        f"Validity: {certificate['EffectiveDateString']} - {certificate['ExpirationDateString']}"

    if verbose:
        print(console_string)

    if return_as_dict:
        return certificate
    return certificate['cert']
