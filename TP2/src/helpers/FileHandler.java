package helpers;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;

import java.util.HashMap;
import security.PBEConfiguration;

/**
 * classe para fazer o handling dos ficheiros de configuração
 * 
 * @authors David, Ricardo 
 *
 */
public class FileHandler {

	/**
	 * Method to read the ciphersuite file that's is ciphered.
	 * 
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	public static InputStream readCiphersuiteFileEncrypted(String filename) throws IOException {
		InputStream inputStream = null;
		inputStream = new FileInputStream(filename);
		return inputStream;
	}

	/**
	 * Method to read the pbe configuration file
	 * 
	 * @param filename
	 * @return
	 */
	public static PBEConfiguration readPBEncryptionFile(String filename) {
		HashMap<String, String> hashmap = getKeyValuesFromFile(filename);

		PBEConfiguration pbe = new PBEConfiguration();
		pbe.setAlgorithm(hashmap.get("PBE"));
		pbe.setSalt(hashmap.get("SALT"));
		pbe.setCounter(Integer.parseInt(hashmap.get("CTR")));

		return pbe;
	}

	/**
	 * Auxiliar method just to read a file and store the configuration in pair
	 * of Key,Value inside a HashMap
	 * 
	 * @param filename
	 * @return
	 */
	public static HashMap<String, String> getKeyValuesFromFile(String filename) {
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
			// simple way to parse, this way is more generic
			HashMap<String, String> hm = new HashMap<String, String>();
			
			String line = br.readLine();
			while (line != null) {
				// if has # it's a comment, so ignore it
				if (!line.startsWith("#")) {
					String[] lineSplitted = line.split(":");
					String key = lineSplitted[0];
					String value = lineSplitted[1].split("#")[0].trim();

					hm.put(key, value);
				}
				line = br.readLine();
			}

			return hm;
		} catch (IOException e) {
			System.out.println("Failed to read the file." + e.getMessage());
		}
		return null;
	}

}
