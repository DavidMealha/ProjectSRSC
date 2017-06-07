# ProjectSRSC (Group SRSC-23)

## Fase 1

### How to setup:
* Run the class TLSServer, specifying the parameters keyStorePassword, entryPassword, serverPbePassword, port. (used: server server serverpbepassword 4443)
* Run the class MyMChatCliente, specifying the parameters username, ipmulticast, port, keyStorePassword, keyStoreEntryPassword. (used: bob 224.10.10.10 8080 bobClient bobClient |OR/AND| alice 224.10.10.10 8080 aliceClient aliceClient |OR/AND| john 224.10.10.10 8080 johnClient johnClient).
* Application password for alice: password
* Application password for bob: bob
* Application password for john: john

### Observations:
* In order to simplify the whole project is just one eclipse project.
* The server access the files in the directory 'database', in a real world application, this folder would be only on the server side.
* The directory 'certificates' is where all the certificates are store to a easier management, but obviously, no one can have access to the .keystore of other users. In a real world application, the server or clients would only have access to their certificate and correspondent key.
* The certificates are signed by a dummy CA, this way, there is only a truststore with only one certificate(of the CA), this way we avoid the constant modifying of the trust stores.
* The naming of the truststore is clienttruststore but its used by everyone, just bad naming.
* The steps to generate the certificates emited by the CA are in the directory 'certificates/certificatesGeneration.txt'.
* The clients also have config files for the TLS handshake, to know where the keystore path is, and when it's needed to load his keystore(when its CLIENTE or CLIENTE-SERVIDOR authentication).
* The authentication type on the tls.config files should be the same.
* The .crypto file stored in the server, is protected with PBE to avoid someone reading on the server, but it's unciphered before sending to the user, since the channel is already secured by TLS. 

## Fase 2

### Observations:
