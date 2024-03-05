from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.backends import default_backend
import os
import sys


#security context


class CipherFiles:
    def __init__(self) -> None:
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        self.backend = default_backend()
        self.cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend
        )

    def cipher_file(self, input_file, output_file):
        padder = padding.PKCS7(128).padder()
        file_cipher = self.cipher.encryptor()

        with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
            out_file.write(self.iv)
            while True:
                block = in_file.read(16)
                if not block:
                    break
                out_file.write(file_cipher.update(padder.update(block)))
            out_file.write(file_cipher.update(padder.finalize()))  # Mueve finalize fuera del bucle
            out_file.write(file_cipher.finalize())

    def decrypter(self, input_file, output_file, key, iv):
        unpadder = padding.PKCS7(128).unpadder()
        cripher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decrypter = cripher.decryptor()

        with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
            iv = in_file.read(16)
            crypt_content = in_file.read()
            decrypt_file = decrypter.update(crypt_content) + decrypter.finalize()
            out_file.write(unpadder.update(decrypt_file) + unpadder.finalize())

    def save_iv_key(self, file_key, iv_file):
        with open(file_key, "wb") as f_key, open(iv_file, "wb") as iv_f:
            f_key.write(self.key)
            iv_f.write(self.iv)

    def load_iv_key(self, file_key, file_iv):
        with open(file_key,'rb') as f_key, open(file_iv,'rb') as iv_f:
            self.key = f_key.read()
            self.iv = iv_f.read()
            self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
