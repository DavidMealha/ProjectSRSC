//aux class to handle the pbe config file
public class PBEConfiguration {
	
	private String algorithm;
	private byte[] salt;
	private int counter;
	
	public PBEConfiguration() {}
	
	public PBEConfiguration(String algorithm, byte[] salt, int counter) {
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

	public byte[] getSalt() {
		return salt;
	}

	public void setSalt(byte[] salt) {
		this.salt = salt;
	}

	public int getCounter() {
		return counter;
	}

	public void setCounter(int counter) {
		this.counter = counter;
	}
	
	
}