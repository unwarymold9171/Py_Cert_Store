def find_windows_cert_by_extention(store:str="My", extention_name:str=None, extention_value:str=None) -> str: # TODO chjange the return type to bytes
    """
    Find a certificate in the Windows certificate store by its extention.
    
    :param store: The name of the certificate store to search in.
    :param extention_name: The name of the extention to search for.
    :param extention_value: The value of the extention to search for.
    :return: The certificate found as `bytes`.
    """

class CertNotExportableError(Exception):
    """
    Raised when the certificate is not exportable.
    """
