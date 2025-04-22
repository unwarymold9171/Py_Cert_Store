copyright_notice = \
'''\
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
# limitations under the License.\
'''

annotations_import = 'from __future__ import annotations'

all_definition = \
'''\
__all__ = {
    "__author__",
    "__copyright__",
    "__version__",
}\
'''

version_number = '__version__ = "{}"'

author_definition = '__author__ = "Unwarymold9171 and individual contributors"'
copyright_definition ='__copyright__ = f"Copyright 2024-2025 {__author__}"'

if __name__ == "__main__":
    with open('cargo.toml', 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith('version ='):
                version_line = line.strip()
                current_version = version_line.split('=')[1].strip().replace('"', '')
                break

    with open('py_cert_store/__about__.py', 'w') as f:
        f.write(copyright_notice + '\n\n')
        f.write(annotations_import + '\n\n')
        f.write(all_definition + '\n\n')
        f.write(version_number.format(current_version) + '\n\n')
        f.write(author_definition + '\n')
        f.write(copyright_definition + '\n')
