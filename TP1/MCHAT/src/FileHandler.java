import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * classe para fazer o handling dos ficheiros de configuração 
 * @author David
 *
 */
public class FileHandler {
	
	/**
	 * Method to write into the file the cipher configuration content already ciphered
	 * @param filename
	 * @param content
	 */
	public static void writeCiphersuiteFile(String filename, byte[] content) {
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
			bw.write(Utils.toHex(content));
			
			// no need to close it.
			//bw.close();
		} catch (IOException e) {
			System.out.println("Failed to write ciphered file." + e.getMessage());
		}
	}
	
	/**
	 * Method to read the crypto configuration file
	 * @param filename
	 */
	public static CipherConfiguration readCiphersuiteFile(String filename){
		//still missing the unciphering of the .crypto file, to do later!!!
		//Since this will be ciphered, this can't be like this, just read the file and return the String
		//Then after the unciphering in the CipherHandler we can parse the information to an object
		HashMap<String, String> hashmap = getKeyValuesFromFile(filename);
		
		CipherConfiguration cipherConfiguration = new CipherConfiguration();
		
		for (Map.Entry<String, String> entry : hashmap.entrySet()) {
			switch(entry.getKey()){
				case "CIPHERSUITE": cipherConfiguration.setCiphersuite(entry.getValue());
					break;
				case "KEYSIZE": cipherConfiguration.setKeySize(Integer.parseInt(entry.getValue()));
					break;
				case "KEYVALUE": cipherConfiguration.setKeyValue(Utils.stringToByteArray(entry.getValue()));
					break;
				case "MAC": cipherConfiguration.setMacAlgorithm(entry.getValue());
					break;
				case "MACKEYSIZE": cipherConfiguration.setMacKeySize(Integer.parseInt(entry.getValue()));
					break;
				case "MACKEYVALUE": cipherConfiguration.setMacKeyValue(Utils.stringToByteArray(entry.getValue()));
					break;
			}
		}
		return cipherConfiguration;
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


