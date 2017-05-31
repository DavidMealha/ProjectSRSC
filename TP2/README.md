# ProjectSRSC (Group SRSC-23)

## Fase 1

### How to setup:


### Observations:
* In order to simplify the whole project is just one eclipse project.
* The server access the files in the directory 'database', in a real world application, this folder would be only on the server side.
* The directory 'certificates' is where all the certificates are store to a easier management, but obviously, no one can have access to the .key of other users. In a real world application, the server or clients would only have access to their certificate and correspondent key.
* The certificates are signed by a dummy CA, this way, there is only a truststore with only one certificate(of the CA), this way we avoid the constant modifying of the trust stores.
* The naming of the truststore is clienttruststore but its used by everyone, just bad naming.
* The steps to generate the certificates emited by the CA are in the directory 'certificates/certificatesGeneration.txt'.

## Fase 2

### Observations:

Steps:
-Create crypto using the FileGenerator, to simplify the server and client are in the same project, but the objective is to the crypto file generator be only on the server side.
-Then, the server sends the crypto content to the client, he can store it, or just have the Object CipherConfiguration stored while he is logged, this way, only when he is authenticated he has access to the ciphersuite information.

O servidor gera o .crypto em clear, e depois quando um user pede o ficheiro, é cifrado com pbe