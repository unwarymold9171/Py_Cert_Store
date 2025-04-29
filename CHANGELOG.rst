Changelog
=========

.. Version 0.3.0
.. -------------
..
.. **WIP** TODO: Update once 0.3.0 is started

Version 0.2.2 : Patch Release
-----------------------------

- Dependencies Updated

Version 0.2.1 : Offical Release
-------------------------------

Bugfixes
~~~~~~~~

- Fixed the ``CertNotFound`` exception not being importable.
- Fixed internal version number not being synced with PyPi's version number.

Version 0.2.0-beta.2
--------------------

New Features
~~~~~~~~~~~~

- Added a "Simplified" function call in the form of ``get_win_cert``.
  - This function is intended to simplify the function calls within the module to a single common use case.
- Expanded the ``find_windows_cert_by_extension`` function parameters to expand where a certificate can be grabbed from.
- Added a new error type ``CertNotFound``.
  - This error is thrown when there are no certificates meeting the parameters for ``find_windows_cert_by_extension``.
- Added a new test case.
  - This test case utilizes pythonnet and .NET calls to act as a truth value to compare the module's outputs to.

Changes
~~~~~~~

- The output for ``find_windows_cert_by_extension`` is now a list of certificates, not just the first certificate that met the input parameters.
- Updated the formatting of the ``Name`` and ``IssuerName`` values to better match what would be given by the equivalent .NET call.

Bugfixes
~~~~~~~~

- The returned bytes for the certificate have been fixed.
- Implemented the ``extension_oid`` function parameter for ``find_windows_cert_by_extension``.
  - Initial release did not do anything with the parameter and took the wrong input type.

Version 0.1.0-beta.1
--------------------

Initial Release
~~~~~~~~~~~~~~~

Initial beta version of Py_Cert_Store. Check the `README <./README.md>`_ for details and how to use.

Issues and feedback can be submitted via `GitHub <https://github.com/unwarymold9171/Py_Cert_Store/issues>`_.
