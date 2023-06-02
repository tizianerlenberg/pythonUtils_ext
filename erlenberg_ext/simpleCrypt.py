import base64, json, os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt(plaintext, password, iterations=390000):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    cyphertext = f.encrypt(plaintext.encode())

    enc_dict = {
        'salt' : (base64.b64encode(salt)).decode('utf-8'),
        'iterations' : iterations,
        'cyphertext' : (base64.b64encode(cyphertext)).decode('utf-8')
    }
    enc_json = json.dumps(enc_dict)
    
    return enc_json

def decrypt(enc_json, password):
    enc_dict = json.loads(enc_json)
    
    salt = base64.b64decode((enc_dict['salt']).encode('utf-8'))
    cyphertext = base64.b64decode((enc_dict['cyphertext']).encode('utf-8'))
    iterations = enc_dict['iterations']
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    plaintext = f.decrypt(cyphertext).decode()
    return plaintext
