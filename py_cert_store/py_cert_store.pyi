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


def find_windows_cert_by_extension(store:str="My", extension_oid:int=None, extension_value:str=None) -> dict[str, str|bytes]:
    """
    Find a certificate in the Windows certificate store by its extension.

    :param store: The name of the certificate store to search in.
    :param extension_oID: The object ID of the extension to search for.
        - This number can be found with the `Cryptography` python package.
    :param extension_value: The value of the extension to search for.
    :return: The certificate found as `bytes`.
    """

class CertNotExportable(Exception): # TODO: Make sure that this is the correct class name for the exception
    """
    Raised when the certificate is not exportable.
    """
