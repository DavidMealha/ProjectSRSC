package application;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;

/**
 * classe para fazer o handling dos ficheiros de configuração
 * 
 * @author David
 *
 */
public class FileHandler {

	/**
	 * Method to write into the file the cipher configuration content already
	 * ciphered
	 * 
	 * @param filename
	 * @param content
	 */
//	public static void writeCiphersuiteFile(String filename, byte[] content) {
//		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
//			bw.write(Utils.toHex(content));
//
//			// no need to close it.
//			// bw.close();
//		} catch (IOException e) {
//			System.out.println("Failed to write ciphered file." + e.getMessage());
//		}
//	}

	/**
	 * Method to read the ciphersuite file that's is ciphered.
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	public static byte[] readCiphersuiteFileEncrypted(String filename) throws IOException {
		Path fileLocation = Paths.get(filename);
		byte[] data = Files.readAllBytes(fileLocation);
		return data;
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
