package application;

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
		super();
		this.algorithm = algorithm;
		this.salt = salt;
		this.counter = counter;
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

}