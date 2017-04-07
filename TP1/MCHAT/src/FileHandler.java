import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.NoSuchPaddingException;

//classe para fazer o handling dos ficheiros de configuração
public class FileHandler {
	
	public static void writeCiphersuiteFile(String filename) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
			
			bw.write(Utils.toHex(CipherHandler.cipherText("ABCABCABC".getBytes())));
			
			// no need to close it.
			//bw.close();

			System.out.println("Done");

		} catch (IOException e) {

			e.printStackTrace();

		}
	}
	
	public static void readCiphersuiteFile(String filename){
		//read the ciphersuite file
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
			String line = br.readLine(); 
			while (line != null) {
				
				line = br.readLine();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	//throw error when the operation mode is ECB, because it's not secure
	public static PBEConfiguration readPBEncryptionFile(String filename){
		PBEConfiguration pbe = new PBEConfiguration();
		
		//read the pbe file
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
			String line = br.readLine(); 
			while (line != null) {
				//if has # it's a comment, so ignore it
				if(!line.startsWith("#")){
					String[] lineSplitted =  line.split(":");
					String key = lineSplitted[0];
					String value = lineSplitted[1].split("#")[0].trim();
					
					if (key.equals("PBE")) {
						pbe.setAlgorithm(value);
					}else if(key.equals("SALT")){
						pbe.setSalt(Utils.stringToByteArray(value));
					}else if(key.equals("CTR")){
						pbe.setCounter(Integer.parseInt(value));
					}
				}
				line = br.readLine();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return pbe;
	}
}


