# pythonUtils_ext
Some personal librarys for python. This module is heavier than "erlenberg" so it is separated.

Install instructions:

```
pip install erlenberg_ext
```

Usage instructions in python program:

```
import erlenberg_ext

cyphertext = erlenberg_ext.simpleCrypt.encrypt('text to encrypt', 'password')
print(cyphertext)

plaintext = erlenberg_ext.simpleCrypt.decrypt(cyphertext, 'password')
print(plaintext)
```

Usage instructions for the specific submodules (e.g. logHandler) can be found in the "information" directory.
