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
 * @author David, Ricardo
 *
 */
public class FileGenerator {

	private static final String LOGFILESDIR = "configs/";
	private static final String PBEEXTENSION = ".pbe";
	private static final String CRYPTOEXTENSION = ".crypto";
	
	public static void main(String[] args)
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException,
			NoSuchProviderException, ClassNotFoundException {
		
		if (args.length != 9) {
			System.out.println("Check if you have inserted all the arguments.");
			System.out.println("args : filename/host password PBEAlgorithm SaltSize PBECounter CiphersuiteAlgorithm KeySize MacAlgorithm MacKeySize");
			System.out.println("e.g  : 224.10.10.10 password PBEWithSHAAnd3KeyTripleDES 8 1024 AES/CBC/PKCS5Padding 256 DES 64");
		} else {
			String filename = args[0];
			String password = args[1];
			String PBEAlgorithm = args[2];
			int PBESaltSize = Integer.parseInt(args[3]);
			int PBECounter = Integer.parseInt(args[4]);
			String CiphersuiteAlgorithm = args[5];
			int CiphersuiteKeySize = Integer.parseInt(args[6]);
			String MacAlgorithm = args[7];
			int MacKeySize = Integer.parseInt(args[8]);
			
			PBEConfiguration pbe = new PBEConfiguration();
//			pbe.setAlgorithm("PBEWITHSHA256AND192BITAES-CBC-BC");
//			pbe.setAlgorithm("PBEWithSHAAnd3KeyTripleDES");
			pbe.setAlgorithm(PBEAlgorithm);
			pbe.setSalt(UtilsBase.toHex(KeyGenerator.generateSalt(PBESaltSize)));
			pbe.setCounter(PBECounter);
		
			createPBE(LOGFILESDIR + filename + PBEEXTENSION, pbe.getAlgorithm(), pbe.getCounter(), pbe.getSalt());
			createCrypto(LOGFILESDIR + filename + CRYPTOEXTENSION, pbe, password, CiphersuiteAlgorithm, CiphersuiteKeySize, MacAlgorithm, MacKeySize);
			
			// just to test if unciphers correctly
			// CipherHandler.uncipherFileWithPBE(password, filename).toString();
		}
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

	/**
	 * method to generate the .crypto file with the content encrypted with PBE.
	 * 
	 * @param filename
	 * @param pbe
	 * @param password
	 * @param algorithm
	 * @param keySize
	 * @param macAlgorithm
	 * @param macKeySize
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws NoSuchProviderException
	 */
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
