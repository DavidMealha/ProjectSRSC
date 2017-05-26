package security;

/**
 * aux class to handle the pbe config file
 * 
 * @authors David, Ricardo 
 *
 */
public class PBEConfiguration {

	private String algorithm;
	private String salt;
	private int counter;

	public PBEConfiguration() {
	}

	public PBEConfiguration(String algorithm, String salt, int counter) {
		this.algorithm = algorithm;
		this.salt = salt;
		this.counter = counter;
	}
	
	public PBEConfiguration(String pbe){
		String[] keyvalues = pbe.split(" | ");
		this.algorithm = keyvalues[1].trim();
		this.salt = keyvalues[4].trim();
		this.counter = Integer.parseInt(keyvalues[7].trim());
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public int getCounter() {
		return counter;
	}

	public void setCounter(int counter) {
		this.counter = counter;
	}
	
	@Override
	public String toString(){
		return "pbe: " + this.algorithm + " | salt: " + this.salt + " | counter: " + this.counter;
	}
}