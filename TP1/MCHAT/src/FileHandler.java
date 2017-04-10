import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.NoSuchPaddingException;

import DatasetParser.QA;

/**
 * classe para fazer o handling dos ficheiros de configuração 
 * @author David
 *
 */
public class FileHandler {
	
	public static void writeCiphersuiteFile(String filename) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
			
			//do this when it will be needed to cipher the .crypto file
			//bw.write(Utils.toHex(CipherHandler.cipherFileWithPBE("ABCABCABC".getBytes())));
			
			// no need to close it.
			//bw.close();

			System.out.println("Done");

		} catch (IOException e) {

			e.printStackTrace();

		}
	}
	
	/**
	 * Method to read the crypto configuration file
	 * @param filename
	 */
	public static void readCiphersuiteFile(String filename){
		//still missing the unciphering of the .crypto file, to do later!!!
		HashMap<String, String> hashmap = getKeyValuesFromFile(filename);
		
		CipherConfiguration cipher = new CipherConfiguration();
		
		for (Map.Entry<String, String> entry : hashmap.entrySet()) {
			switch(entry.getKey()){
				case "CIPHERSUITE": cipher.setCiphersuite(entry.getValue());
					break;
				case "KEYSIZE": cipher.setKeySize(Integer.parseInt(entry.getValue()));
					break;
				case "KEYVALUE": cipher.setKeyValue(Utils.stringToByteArray(entry.getValue()));
					break;
				case "MAC": cipher.setMacAlgorithm(entry.getValue());
					break;
				case "MACKEYSIZE": cipher.setMacKeySize(Integer.parseInt(entry.getValue()));
					break;
				case "MACKEYVALUE": cipher.setMacKeyValue(Utils.stringToByteArray(entry.getValue()));
					break;
			}
		}
	}
	
	/**
	 * Method to read the pbe configuration file
	 * @param filename
	 * @return
	 */
	public static PBEConfiguration readPBEncryptionFile(String filename){
		HashMap<String, String> hashmap = getKeyValuesFromFile(filename);
		
		PBEConfiguration pbe = new PBEConfiguration();
		pbe.setAlgorithm(hashmap.get("PBE"));
		pbe.setSalt(Utils.stringToByteArray(hashmap.get("SALT")));
		pbe.setCounter(Integer.parseInt(hashmap.get("CTR")));

		return pbe;
	}
	
	/**
	 * Auxiliar method just to read a file and store the configuration in pair of Key,Value inside a HashMap
	 * @param filename
	 * @return
	 */
	public static HashMap<String, String> getKeyValuesFromFile(String filename){
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
			//simple way to parse, this way is more generic
			HashMap<String, String> hm = new HashMap<String, String>();
			
			String line = br.readLine(); 
			while (line != null) {
				//if has # it's a comment, so ignore it
				if(!line.startsWith("#")){
					String[] lineSplitted =  line.split(":");
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


