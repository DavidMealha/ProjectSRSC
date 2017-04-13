package filegenerator;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import application.CipherConfiguration;
import application.CipherHandler;
import application.PBEConfiguration;
import application.Utils;
import application.UtilsBase;

/**
 * Class to generate the .pbe and .crypto files.
 * 
 * @author David
 *
 */
public class FileGenerator {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException,
			NoSuchProviderException, ClassNotFoundException {
		// create PBEConfiguration to ease the exchange of values between
		// methods
		PBEConfiguration pbe = new PBEConfiguration();
//		pbe.setAlgorithm("PBEWITHSHA256AND192BITAES-CBC-BC");
		pbe.setAlgorithm("PBEWithSHAAnd3KeyTripleDES");
		pbe.setSalt(UtilsBase.toHex(KeyGenerator.generateSalt(8)));
		pbe.setCounter(1024);

		// how to generate the counter?
		createPBE("configs/224.9.9.9.pbe", pbe.getAlgorithm(), pbe.getCounter(), pbe.getSalt());

		createCrypto("configs/224.9.9.9.crypto", pbe, "password", "AES/CBC/PKCS5Padding", 256, "DES", 64);

		CipherHandler.uncipherFileWithPBE("password", "224.9.9.9").toString();

	}

	/**
	 * Method to store into a file the configuration for the PBEncryption
	 * 
	 * @param filename
	 * @param algorithm,
	 *            pbealgorithm(e.g PBEWithHmacSHA256AndAES_256)
	 * @param counter
	 * @param saltSize,
	 *            size of the salt generate(e.g 8bytes equals to 64bits, etc..)
	 * @throws NoSuchAlgorithmException
	 */
	public static void createPBE(String filename, String algorithm, int counter, String salt)
			throws NoSuchAlgorithmException {
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
			bw.write("PBE: " + algorithm + "\n");
			bw.write("SALT: " + salt + "\n");
			bw.write("CTR: " + counter);

			// no need to close it.
			// bw.close();
			System.out.println("PBE File Created!");
		} catch (IOException e) {
			System.out.println("Failed to write ciphered file." + e.getMessage());
		}
	}

	public static void createCrypto(String filename, PBEConfiguration pbe, String password, String algorithm,
			int keySize, String macAlgorithm, int macKeySize) throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException {

		// create key for the cipher suite
		SecureRandom random = new SecureRandom();
		byte[] key = Utils.createKey(keySize, random, algorithm.split("/")[0]);

		// create key for the mac
		SecureRandom random2 = new SecureRandom();
		byte[] macKey = Utils.createKey(macKeySize, random2, macAlgorithm.split("/")[0]);

		CipherConfiguration cipherConfiguration = new CipherConfiguration();
		cipherConfiguration.setCiphersuite(algorithm);
		cipherConfiguration.setKeySize(keySize);
		cipherConfiguration.setKeyValue(Utils.toHex(key));
		cipherConfiguration.setMacAlgorithm(macAlgorithm);
		cipherConfiguration.setMacKeySize(macKeySize);
		cipherConfiguration.setMacKeyValue(Utils.toHex(macKey));

		System.out.println(cipherConfiguration.toString());

		// writing to file part
		OutputStream oStream = new FileOutputStream(filename);
		CipherHandler.cipherFileWithPBE(password, pbe, cipherConfiguration, oStream);
	}

}
