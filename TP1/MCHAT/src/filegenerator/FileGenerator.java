package filegenerator;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import application.PBEConfiguration;
import application.Utils;

public class FileGenerator {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		//create PBEConfiguration to ease the exchange of values between methods
		PBEConfiguration pbe = new PBEConfiguration();
		pbe.setAlgorithm("PBEWITHSHA256AND192BITAES-CBC-BC");
		pbe.setSalt(Utils.toHex(KeyGenerator.generateSalt(16)));
		pbe.setCounter(10);
		
		//how to generate the counter?
		createPBE("configs/224.9.9.9.pbe", pbe.getAlgorithm(), pbe.getCounter(), pbe.getSalt());
		
		createCrypto("configs/224.9.9.9.crypto", pbe, "password", "AES/CTR/NoPadding", 128, "HMacSHA1", 60);

	}
	
	/**
	 * Method to store into a file the configuration for the PBEncryption
	 * @param filename
	 * @param algorithm, pbealgorithm(e.g PBEWithHmacSHA256AndAES_256)
	 * @param counter
	 * @param saltSize, size of the salt generate(e.g 8bytes equals to 64bits, etc..)
	 * @throws NoSuchAlgorithmException
	 */
	public static void createPBE(String filename, String algorithm, int counter, String salt) throws NoSuchAlgorithmException{
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
			bw.write("PBE: " + algorithm + "\n");
			bw.write("SALT: " + salt + "\n");
			bw.write("CTR: " + counter);
			
			// no need to close it.
			//bw.close();
			System.out.println("PBE File Created!");
		} catch (IOException e) {
			System.out.println("Failed to write ciphered file." + e.getMessage());
		}
	}
	
	public static void createCrypto(String filename, PBEConfiguration pbe, String password, String algorithm, int keySize, 
			String macAlgorithm, int macKeySize) {

		String fileContent = "CIPHERSUITE: " + algorithm + "\n" + 
							 "KEYSIZE: " + keySize + "\n" + 
							 "KEYVALUE: " + "" + "\n" +
					 		 "MAC: " + macAlgorithm + "\n" + 
				 		 	 "MACKEYSIZE: " + macKeySize + "\n" +
				 		 	 "MACKEYVALUE: " + "" + "\n";
							 
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
			
			bw.write(fileContent);
			// no need to close it.
			//bw.close();
			System.out.println("Crypto File Created!");
		} catch (IOException e) {
			System.out.println("Failed to write ciphered file." + e.getMessage());
		}
	}

}
