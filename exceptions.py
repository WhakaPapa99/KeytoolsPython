# exceptions.py

class KeyStoreError(Exception):
    pass

class PasswordIncorrectaError(KeyStoreError):
    pass

class AliasDuplicadoError(KeyStoreError):
    pass

class AlmacenNoEncontradoError(KeyStoreError):
    pass