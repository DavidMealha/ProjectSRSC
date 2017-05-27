Steps:
-Create crypto using the FileGenerator, to simplify the server and client are in the same project, but the objective is to the crypto file generator be only on the server side.
-Then, the server sends the crypto content to the client, he can store it, or just have the Object CipherConfiguration stored while he is logged, this way, only when he is authenticated he has access to the ciphersuite information.

O servidor gera o .crypto em clear, e depois quando um user pede o ficheiro, é cifrado com pbe