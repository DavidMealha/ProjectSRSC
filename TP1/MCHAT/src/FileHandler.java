import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

//classe para fazer o handling dos ficheiros de configuração
public class FileHandler {

	public static void readConfigurationFile(String filename){
		
	}
	
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
					String value = lineSplitted[1];
					
					if (key == "PBE") {
						pbe.setAlgorithm(value);
					}else if(key == "SALT"){
						pbe.setSalt(Utils.stringToByteArray(value));
					}else if(key == "CTR"){
						pbe.setCounter(Integer.parseInt(value));
					}
					
					line = br.readLine();
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return pbe;
	}
}


