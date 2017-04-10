import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
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
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static void cipherFileWithPBE(String password, String multicastAddress) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		//before putting the password here, we should hash it, also authenticate with the hash.
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		
		PBEConfiguration pbe = FileHandler.readPBEncryptionFile(multicastAddress + ".pbe");
		
		//e.g ("PBEWithHmacSHA256AndAES_256")
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbe.getAlgorithm());
		
		//The key is created
		SecretKey key = keyFactory.generateSecret(keySpec);
		
		//The params salt and counter are added to the PBE
		PBEParameterSpec paramSpec = new PBEParameterSpec(pbe.getSalt(), pbe.getCounter());
		
		Cipher cipher = Cipher.getInstance(pbe.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
		
		byte[] cipheredFile = cipher.doFinal("FileStuff..:".getBytes());
		
		FileHandler.writeCiphersuiteFile(multicastAddress + ".crypto", cipheredFile);
	}
	
	/**
	 * Method to uncipher the file with the ciphering configuration with PBEncryption
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static void uncipherFileWithPBE(String password, String multicastAddress) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		//won't be able to do this because it's ciphered.., only if i parse to this object after unciphering
		CipherConfiguration cipherConfiguration = FileHandler.readCiphersuiteFile(multicastAddress + ".crypto");
		
		byte[] cipheredFile = Utils.stringToByteArray("FileStuffEncrypted...");
		
		//Create PBEKeySpec for the password given
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		
		PBEConfiguration pbe = FileHandler.readPBEncryptionFile(multicastAddress + ".pbe");
		
		//e.g ("PBEWithHmacSHA256AndAES_256")
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbe.getAlgorithm());
		
		//the key is created
		SecretKey key = keyFactory.generateSecret(keySpec);
		
		//The params salt and counter are added to the PBE
		PBEParameterSpec paramSpec = new PBEParameterSpec(pbe.getSalt(), pbe.getCounter());
		
		Cipher cipher = Cipher.getInstance(pbe.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
		
		cipher.doFinal(cipheredFile);
		//now that i have the plain text unciphered, can parse to CipherConfiguration class
	}
}
