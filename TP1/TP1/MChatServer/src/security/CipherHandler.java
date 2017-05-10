package security;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import auxiliaryClasses.UtilsBase;
import fileManagement.FileHandler;

/**
 * class para encriptar e desencriptar os byte arrays que serão enviados e
 * recebidos nos datagram packets
 * 
 * @author David
 *
 */
public class CipherHandler {

	/**
	 * 
	 * @param buffer
	 * @param cipherConfiguration
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IllegalStateException
	 */
	public static byte[] cipherText(byte[] buffer, CipherConfiguration cipherConfiguration)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			IllegalStateException {
		// check if it's ecb, and then add no IV? or just assume it will use
		// safe modes, like CBC or CTR
		//when it's ECB or CBC the buffer size should be multiple of the block size.

		// generate an initialization vector, with a counter
		// IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
		byte[] ivBytes = new byte[] { 0x08, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x08, 0x06, 0x05, 0x04, 0x03,
				0x02, 0x01, 0x00 };

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

		SecretKey key = new SecretKeySpec(UtilsBase.hexStringToByteArray(cipherConfiguration.getKeyValue()), cipherConfiguration.getCiphersuite().split("/")[0]);

		// get instance of cipher
		Cipher cipher = Cipher.getInstance(cipherConfiguration.getCiphersuite(), "BC");

		// get instance of MAC
		Mac mac = Mac.getInstance(cipherConfiguration.getMacAlgorithm(), "BC");

		// generate the mac key
		Key macKey = new SecretKeySpec(UtilsBase.hexStringToByteArray(cipherConfiguration.getMacKeyValue()), cipherConfiguration.getMacAlgorithm());

		// initialize encryption mode
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

		// creates byte array with the size of the ciphered text and mac
		byte[] cipherText = new byte[cipher.getOutputSize(buffer.length + mac.getMacLength())];

		int ctLength = cipher.update(buffer, 0, buffer.length, cipherText, 0);
		
		mac.init(macKey);
		mac.update(buffer);

		ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), cipherText, ctLength);

		return cipherText;
	}

	/**
	 * 
	 * @param buffer
	 * @param cipherConfiguration
	 * @return
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ShortBufferException 
	 */
	public static byte[] uncipherText(byte[] buffer, CipherConfiguration cipherConfiguration)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, UnsupportedEncodingException,
			InvalidAlgorithmParameterException, ShortBufferException {

		byte[] ivBytes = new byte[] { 0x08, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x08, 0x06, 0x05, 0x04, 0x03,
				0x02, 0x01, 0x00 };

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

		// read the key that was generated in the file
		SecretKey key = new SecretKeySpec(UtilsBase.hexStringToByteArray(cipherConfiguration.getKeyValue()), cipherConfiguration.getCiphersuite().split("/")[0]);

		// get instance of cipher
		Cipher cipher = Cipher.getInstance(cipherConfiguration.getCiphersuite(), "BC");

		// get instance of MAC
		Mac mac = Mac.getInstance(cipherConfiguration.getMacAlgorithm(), "BC");
		
		// generate the mac key
		Key macKey = new SecretKeySpec(UtilsBase.hexStringToByteArray(cipherConfiguration.getMacKeyValue()), cipherConfiguration.getMacAlgorithm());

		// generate byte array for the key MAC
		byte[] macKeyBytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		
		int ctLength = buffer.length;
		byte[] plainText = cipher.doFinal(buffer, 0, ctLength);
			
		int messageLength = plainText.length - mac.getMacLength();

		// Verificaao Mac
		mac.init(macKey);
		mac.update(plainText, 0, messageLength);

		byte[] messageHash = new byte[mac.getMacLength()];
		System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

		return plainText;
	}

	/**
	 * Method to cipher the file with the ciphering configuration with
	 * PBEncryption
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public static CipherOutputStream cipherFileWithPBE(String password, PBEConfiguration pbe,
			CipherConfiguration cipherConfiguration, OutputStream outStream)
			
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
				InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		// before putting the password here, we should hash it, also
		// authenticate with the hash.
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());

		// e.g ("PBEWithHmacSHA256AndAES_256")
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbe.getAlgorithm());

		// The key is created
		SecretKey key = keyFactory.generateSecret(keySpec);

		// The params salt and counter are added to the PBE
		PBEParameterSpec paramSpec = new PBEParameterSpec(pbe.getSalt().getBytes(), pbe.getCounter());

		Cipher cipher = Cipher.getInstance(pbe.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

		SealedObject sealedObject = new SealedObject(cipherConfiguration, cipher);
		// byte[] cipheredFile = cipher.doFinal(fileContent.getBytes());

		CipherOutputStream cos = new CipherOutputStream(outStream, cipher);
		ObjectOutputStream outputStream = new ObjectOutputStream(cos);
		outputStream.writeObject(sealedObject);
		outputStream.close();
		return cos;
	}

	/**
	 * Method to uncipher the file with the ciphering configuration with
	 * PBEncryption
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public static CipherConfiguration uncipherFileWithPBE(String password, String multicastAddress)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException,
			ClassNotFoundException {
		// read the ciphered file, that is saved as a ciphered object in a whole
		InputStream iStream = FileHandler.readCiphersuiteFileEncrypted("configs/" + multicastAddress + ".crypto");

		PBEConfiguration pbe = FileHandler.readPBEncryptionFile("configs/" + multicastAddress + ".pbe");

		// Create PBEKeySpec for the password given
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());

		// e.g ("PBEWithHmacSHA256AndAES_256")
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbe.getAlgorithm());

		// the key is created
		SecretKey key = keyFactory.generateSecret(keySpec);

		// The params salt and counter are added to the PBE
		PBEParameterSpec paramSpec = new PBEParameterSpec(pbe.getSalt().getBytes(), pbe.getCounter());

		Cipher cipher = Cipher.getInstance(pbe.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

		// read file
		CipherInputStream cipherInputStream = new CipherInputStream(iStream, cipher);
		ObjectInputStream inputStream = new ObjectInputStream(cipherInputStream);
		SealedObject sealedObject;
		sealedObject = (SealedObject) inputStream.readObject();
		return (CipherConfiguration) sealedObject.getObject(cipher);
	}
}
