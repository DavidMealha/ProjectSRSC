import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * class para encriptar e desencriptar os byte arrays que serão enviados e recebidos nos datagram packets
 * @author David
 *
 */
public class CipherHandler {

	/**
	 * 
	 * @param buffer
	 * @return buffer encriptado
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] cipherText(byte[] buffer, String multicastAddress, String ciphersuite, int keySize, byte[] keyValue, String macAlgorithm, int macKeySize, byte[] macKeyValue) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
		//read configuration file
		FileHandler.readCiphersuiteFile(multicastAddress + ".crypto");
		
		//get instance of cipher
		Cipher cipher = Cipher.getInstance(ciphersuite, "BC");
//		cipher.init(Cipher.ENCRYPT_MODE,
//	            new SecretKeySpec(keyBytes, "DESede"),
//	            new IvParameterSpec(ivBytes));
		
		return buffer;
	}
	
	public static void decipherText(byte[] buffer){
		
	}
	
	/**
	 * Method to cipher the file with the ciphering configuration with PBEncryption
	 */
	public static void cipherFileWithPBE(){
		
	}
	
	/**
	 * Method to uncipher the file with the ciphering configuration with PBEncryption
	 */
	public static void uncipherFileWithPBE(){
		
	}
}
