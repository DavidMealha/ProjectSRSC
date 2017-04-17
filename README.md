# ProjectSRSC (Group SRSC-23)

### 51171 David Mealha
### 41951 Ricardo Silva

## Fase 1 (Folder MCHAT)

### How to setup:
* FileGenerator.java is used to generate the .pbe and .crypto files.	
* There are already files created for two addresses (224.10.10.10 and 224.9.9.9).
* Use the password "password" to generate the .crypto, this is hardcoded because in the Fase 2 it's when it's needed to authenticate the user. This way it simplifies the interaction between the user and the chat.
* Run the class MChatCliente.
* The arguments are the same.

### Observations:
* The password used for the PBE is always the same, just to be easier to debug and test, in the Fase 2 the user is authenticated by a REST Server.
* Initialization Vector is always created in the CipherHandler class, but only user when it's needed.


## Fase 2 (Folder MChatServer & MChat_Client_Communication)

### How to setup:
* Communication Client-Server not working due to invalid SSL certificates
* Messages between client-server with pbe encrypton is implemented but not tested, because the error mentioned above.
