# AES_FILE_ENCRYPTION

###Note, smaller passwords will be looped to create a larger one.

<br>How to use:
<br>Use the ``make`` command to generate a compiled version of the main.c code.
<br>Use the ``make clean`` command to remove ALL generated files.
<br>Use the ``make rebuild`` command to remove ALL generated files and rebuild.
<br>Provide an ``input.txt``, or any other text file, that includes the data you wish to encrypt.
<br>
<br>To encrypt data:
<br>Default Locations: ``./bin/aes -e input/input1.txt``
<br>Confirm that you wish to encrypt the data in [input.txt].
<br>Provide a [password], which will act as the initial key for the AES encryption algorithm.
<br>A new file will appear in your current directory, labeled: ``aes_encrypted_text000.bin``.
<br>
<br>To decrypt:
<br>WIP. Not implimented.

make rebuild && ./bin/aes -e input/input1.txt && ./bin/aes -d aes128_encrypted_text000.bin
