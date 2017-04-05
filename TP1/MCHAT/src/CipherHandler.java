import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//class para encriptar e desencriptar os byte arrays que serão enviados e recebidos nos datagram packets
public class CipherHandler {

	/**
	 * 
	 * @param buffer
	 * @return buffer encriptado
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] cipherText(byte[] buffer) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
		//read configuration file
		
		//get instance of cipher
		Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE,
	            new SecretKeySpec(keyBytes, "DESede"),
	            new IvParameterSpec(ivBytes));
	}
	
	public static void decipherText(byte[] buffer){
		
	}
}
