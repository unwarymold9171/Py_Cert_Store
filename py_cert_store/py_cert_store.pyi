def find_windows_cert_by_extention(store:str="My", extention_oid:int=None, extention_value:str=None) -> str: # TODO change the return type to a dictionary (or list of dictionarys)
    """
    Find a certificate in the Windows certificate store by its extention.
    
    :param store: The name of the certificate store to search in.
    :param extention_oID: The object ID of the extention to search for.
        - This number can be found with the `Cryptography` python package.
    :param extention_value: The value of the extention to search for.
    :return: The certificate found as `bytes`.
    """

class CertNotExportable(Exception): # TODO: Make sure that this is the correct class name for the exception
    """
    Raised when the certificate is not exportable.
    """
