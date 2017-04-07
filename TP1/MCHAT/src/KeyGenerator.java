
public class KeyGenerator {

	public static byte[] generateSalt(){
		return new byte[10];
	}
	
	public void generateCiphersuite(String password){
		//the password needs to firstly be hashed, in order to later be compared with the hash of the pwd in the server
		
	}
}
