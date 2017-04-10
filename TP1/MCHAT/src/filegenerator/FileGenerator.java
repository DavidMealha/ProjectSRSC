package filegenerator;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class FileGenerator {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		//how to generate the counter?
		createPBE("configs/224.9.9.9.pbe", "PBEWITHSHA256AND192BITAES-CBC-BC", 10, 8);
		
		//createCipherSuite(params)

	}
	
	/**
	 * Method to store into a file the configuration for the PBEncryption
	 * @param filename
	 * @param algorithm, pbealgorithm(e.g PBEWithHmacSHA256AndAES_256)
	 * @param counter
	 * @param saltSize, size of the salt generate(e.g 8bytes equals to 64bits, etc..)
	 * @throws NoSuchAlgorithmException
	 */
	public static void createPBE(String filename, String algorithm, int counter, int saltSize) throws NoSuchAlgorithmException{
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
			bw.write("PBE: " + algorithm + "\n");
			bw.write("SALT: " + Utils.toHex(KeyGenerator.generateSalt(saltSize)) + "\n");
			bw.write("CTR: " + counter);
			
			// no need to close it.
			//bw.close();
			System.out.println("PBE File Created!");
		} catch (IOException e) {
			System.out.println("Failed to write ciphered file." + e.getMessage());
		}
	}

}
