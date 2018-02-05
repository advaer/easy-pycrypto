from Crypto.Cipher import AES
from Crypto import Random
from hashlib import sha256
from base64 import urlsafe_b64encode, urlsafe_b64decode

# encode password to 24 bytes (192 bit) key
encode_key = lambda raw_key: urlsafe_b64encode(sha256(raw_key.encode()).digest()).decode()

# Main encrypt logic
class MyCryptAES(object):
    """
    Encrypt Logic
    """

    def __init__(self, key):
        self._bs  = 16 # block size
        self._key = urlsafe_b64decode(key)

    def _pad(self, inp_str):
        """Pad input string to correct length

        :param inp_str: raw secret unicode string
        :return: byte string with length _bs x n
        """
        b_str = inp_str.encode()
        str_pad = self._bs - len(b_str) % self._bs
        return b_str + ((str_pad) * chr(str_pad)).encode()

    @staticmethod
    def _unpad(secret_str):
        """Unpad ending chars

        :param secret_str: byte string with n chars at the end where ord(char) == n
        :return: byte secret string
        """
        return secret_str[:-secret_str[len(secret_str)-1]]

    def encrypt(self, name):
        """Encrypt text

        :param name: input text to encrypt
        :return: encrypted unicode string
        """
        name = self._pad(name)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self._key, AES.MODE_CFB, iv)
        return urlsafe_b64encode(iv + cipher.encrypt(name)).decode()

    def decrypt(self, secret):
        """Decrypt text

        :param secret: encrypted text unicode string
        :return: decrypted unicode string
        """
        name = urlsafe_b64decode(secret)
        iv = name[:AES.block_size]
        cipher = AES.new(self._key, AES.MODE_CFB, iv )
        return self._unpad(cipher.decrypt(name[AES.block_size:])).decode()

def encrypt(password, text):
    """Encrypt helper function

    :param password: unicode string password
    :param text: unicode string text to encrypt
    :return:unicode encrypted string
    """
    cipher = MyCryptAES(encode_key(password))
    return cipher.encrypt(text)
    
def decrypt(password, secret):
    """Decrypt helper function

    :param password: unicode string password
    :param secret: unicode string encrypted text
    :return: unicode string decrypted text
    """
    cipher = MyCryptAES(encode_key(password))
    return cipher.decrypt(secret)

if __name__ == '__main__':
    secret_text = 'My super-duper secret text'
    password = 'pswrd'
    assert secret_text == decrypt(password, encrypt(password, secret_text))
