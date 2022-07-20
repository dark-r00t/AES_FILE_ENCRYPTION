# AES_FILE_ENCRYPTION

###Note, smaller passwords will be looped to create a larger one.

<br>How to use:
<br>Use the ``make`` command to generate a compiled version of the main.c code.
<br>Provide an ``input.txt``, or any other text file, that includes the data you wish to encrypt.
<br>
<br>To encrypt data:
<br>``./run -e input.txt``
<br>Confirm that you wish to encrypt the data in [input.txt].
<br>Provide a [password], which will act as the initial key for the AES encryption algorithm.
<br>A new file will appear in your current directory, labeled: ``aes_encrypted_text000.bin``.
<br>
<br>To decrypt:
<br>WIP. Not implimented.

