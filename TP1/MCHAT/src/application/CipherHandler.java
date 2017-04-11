package application;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.tls.HashAlgorithm;

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
	 * @return buffer encriptado
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalStateException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] cipherText(byte[] buffer, CipherConfiguration cipherConfiguration)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			IllegalStateException {
		// check if it's ecb, and then add no IV? or just assume it will use
		// safe modes, like CBC or CTR

		// create a secure random
		SecureRandom random = new SecureRandom();

		// generate an initialization vector, with a counter
		IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);

		// generate a random key, with some bits, and with a random number
		// (cipherConfiguration.getKeyValue())
		// (cipherConfiguration.getKeySize())
		Key key = Utils.createKey(256, random);

		// get instance of cipher
		Cipher cipher = Cipher.getInstance(cipherConfiguration.getCiphersuite(), "BC");

		// get instance of MAC
		Mac mac = Mac.getInstance(cipherConfiguration.getMacAlgorithm(), "BC");

		// generate byte array for the key MAC
		byte[] macKeyBytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

		// generate the mac key
		Key macKey = new SecretKeySpec(macKeyBytes, cipherConfiguration.getMacAlgorithm());

		// initialize encryption mode
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

		// creates byte array with the size of the ciphered text and mac
		byte[] cipherText = new byte[cipher.getOutputSize(buffer.length + mac.getMacLength())];

		int ctLength = cipher.update(buffer, 0, buffer.length, cipherText, 0);

		mac.init(macKey);
		mac.update(buffer);

		ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), cipherText, ctLength);

		return buffer;
	}

	public static void decipherText(byte[] buffer) {

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
	 */
	public static byte[] cipherFileWithPBE(String password, PBEConfiguration pbe, String fileContent)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// before putting the password here, we should hash it, also
		// authenticate with the hash.
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());

		// PBEConfiguration pbe =
		// FileHandler.readPBEncryptionFile(multicastAddress + ".pbe");

		// e.g ("PBEWithHmacSHA256AndAES_256")
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbe.getAlgorithm());

		// The key is created
		SecretKey key = keyFactory.generateSecret(keySpec);

		// The params salt and counter are added to the PBE
		PBEParameterSpec paramSpec = new PBEParameterSpec(pbe.getSalt().getBytes(), pbe.getCounter());

		Cipher cipher = Cipher.getInstance(pbe.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

		byte[] cipheredFile = cipher.doFinal(fileContent.getBytes());

		System.out.println("CIPHERED FILE IN CIPHER METHOD: " + UtilsBase.toHex(cipheredFile));
		return cipheredFile;
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
	 */
	public static CipherConfiguration uncipherFileWithPBE(String password, String multicastAddress)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		// read the ciphered file, that is save as a byte[], if stored as string
		// it gives problems
		byte[] cipheredFile = FileHandler.readCiphersuiteFileEncrypted("configs/" + multicastAddress + ".crypto");

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

		System.out.println("CIPHERED FILE IN UNCIPHER METHOD: " + UtilsBase.toHex(cipheredFile));
		byte[] uncipheredFile = cipher.doFinal(cipheredFile);
		String uncipheredContent = new String(uncipheredFile, "UTF-8");
		System.out.println("=================================");
		System.out.println("OUTPUT DO .CRYPTO:\n" + uncipheredContent);

		// now that i have the plain text unciphered, can parse to
		// CipherConfiguration class
		return parseFileContentToCipherConfiguration(uncipheredContent);
	}

	/**
	 * Auxiliar method to parse the unciphered file content into the object
	 * CipherConfiguration, in order to have all the information of the
	 * ciphersuite in a structured way.
	 * 
	 * @param fileContent
	 * @return
	 */
	private static CipherConfiguration parseFileContentToCipherConfiguration(String fileContent) {
		String[] splitLines = fileContent.split("\n");
		HashMap<String, String> ciphersuiteValues = new HashMap<String, String>();

		for (String line : splitLines) {
			String[] lineSplitted = line.split(":");
			String key = lineSplitted[0];
			String value = lineSplitted[1].split("#")[0].trim();
			ciphersuiteValues.put(key, value);
		}

		CipherConfiguration cipherConfiguration = new CipherConfiguration();
		for (Map.Entry<String, String> entry : ciphersuiteValues.entrySet()) {
			switch (entry.getKey()) {
			case "CIPHERSUITE":
				cipherConfiguration.setCiphersuite(entry.getValue());
				break;
			case "KEYSIZE":
				cipherConfiguration.setKeySize(Integer.parseInt(entry.getValue()));
				break;
			case "KEYVALUE":
				cipherConfiguration.setKeyValue(UtilsBase.stringToByteArray(entry.getValue()));
				break;
			case "MAC":
				cipherConfiguration.setMacAlgorithm(entry.getValue());
				break;
			case "MACKEYSIZE":
				cipherConfiguration.setMacKeySize(Integer.parseInt(entry.getValue()));
				break;
			case "MACKEYVALUE":
				cipherConfiguration.setMacKeyValue(UtilsBase.stringToByteArray(entry.getValue()));
				break;
			}
		}

		return cipherConfiguration;
	}
}
