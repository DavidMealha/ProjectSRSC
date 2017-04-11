package application;

public class CipherConfiguration {
	private String ciphersuite;
	private int keySize;
	private byte[] keyValue;
	private String macAlgorithm;
	private int macKeySize;
	private byte[] macKeyValue;

	public CipherConfiguration() {
	}

	public String getCiphersuite() {
		return ciphersuite;
	}

	public void setCiphersuite(String ciphersuite) {
		this.ciphersuite = ciphersuite;
	}

	public int getKeySize() {
		return keySize;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}

	public byte[] getKeyValue() {
		return keyValue;
	}

	public void setKeyValue(byte[] keyValue) {
		this.keyValue = keyValue;
	}

	public String getMacAlgorithm() {
		return macAlgorithm;
	}

	public void setMacAlgorithm(String macAlgorithm) {
		this.macAlgorithm = macAlgorithm;
	}

	public int getMacKeySize() {
		return macKeySize;
	}

	public void setMacKeySize(int macKeySize) {
		this.macKeySize = macKeySize;
	}

	public byte[] getMacKeyValue() {
		return macKeyValue;
	}

	public void setMacKeyValue(byte[] macKeyValue) {
		this.macKeyValue = macKeyValue;
	}

}
