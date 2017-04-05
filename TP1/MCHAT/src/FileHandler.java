import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

//classe para fazer o handling dos ficheiros de configuração
public class FileHandler {

	public void readConfigurationFile(String filename){
		
	}
	
	//aux class to handle the pbe config file
	public class PBEConfiguration {
		private String algorithm;
		private byte[] salt;
		private int counter;
		
		public PBEConfiguration(String algorithm, byte[] salt, int counter) {
			super();
			this.algorithm = algorithm;
			this.salt = salt;
			this.counter = counter;
		}
	}
	
	public void readPBEncryptionFile(String filename){
		PBEConfiguration pbe = null;
		
		//read the pbe file
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
			String line = br.readLine(); 
			while (line != null) {
				
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public List<QueryString> readFile(){
		// format of each line (id:query)
//		HashMap<String, String> queries = new HashMap<String, String>();
		//instead have something like this, and add new QueryString(...)
		List<QueryString> listQueries = new ArrayList<QueryString>();
		
		try (BufferedReader br = new BufferedReader(new FileReader(queriesPath))) {
			String line = br.readLine(); 
//			System.out.println("Line read from queries: " + line);
			while (line != null) {
				StringTokenizer lineTokens = new StringTokenizer(line, ":");
				//need to remove the : because some queries have : in the text, which leads to wrong tokenization
				//those replaces are due to a strange bug in the first query parse...
				listQueries.add(new QueryString(lineTokens.nextToken().replace("ï", "").replace("»", "").replace("¿", ""), lineTokens.nextToken("").replace(":", "").replace("\"", "")));		
				line = br.readLine();
//				System.out.println("Line read	 from queries: " + line);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return listQueries;
	}
}
