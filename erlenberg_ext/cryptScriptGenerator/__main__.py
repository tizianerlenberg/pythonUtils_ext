import base64
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

def encrypt(plaintext, password, length=32, iterations=390000):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    cyphertext = f.encrypt(plaintext.encode())

    enc_dict = {
        'length' : 32,
        'salt' : (base64.b64encode(salt)).decode('utf-8'),
        'iterations' : iterations,
        'cyphertext' : (base64.b64encode(cyphertext)).decode('utf-8')
    }
    enc_json = json.dumps(enc_dict)
    
    return enc_json

toPrepend=r'''import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

def decrypt(enc_json, password):
    enc_dict = json.loads(enc_json)
    
    salt = base64.b64decode((enc_dict['salt']).encode('utf-8'))
    cyphertext = base64.b64decode((enc_dict['cyphertext']).encode('utf-8'))
    length = enc_dict['length']
    iterations = enc_dict['iterations']
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    plaintext = f.decrypt(cyphertext).decode()
    return plaintext

'''

toAppend = r'''
toExecute = ''
while(True):
    try:
        password = getpass("Enter Password for Decryption: ")
        toExecute = decrypt(cyphertext, password)
        break
    except:
        print('\nSomething went wrong, do you want to try again? (y/n) ', end='')
        if (input() == 'y'):
            continue
        else:
            exit()
    
print('Successfully decrypted')
print('Executing script')
print()
exec(toExecute)
'''

def generateString(src):
    password = getpass("Enter Password for Encryption: ")
    cyphertext = encrypt(src, password)
    result = (
        toPrepend + 
        f'''cyphertext = '{cyphertext}'\n''' + 
        toAppend
    )
    
    return result

def generateFile(src, dest):
    content = ''
    with open(src, 'r') as file:
        content = file.read()
    
    toWrite = generateString(content)

    with open(dest, 'w') as file:
        file.write(toWrite)
    
    print('Success')

def main():
    import argparse

    parser = argparse.ArgumentParser(description=
        """Tool to generate self decrypting script""")
    parser.add_argument("source", help = "path to source file")
    parser.add_argument("destination", help = "path to destination file")
    args = parser.parse_args()

    generateFile(args.source, args.destination)

if __name__ == "__main__":
	main()
