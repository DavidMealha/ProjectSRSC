package application;

import java.io.Serializable;

/**
 * Class to give some structure to the content of the .crypto file. 
 * @authors David, Ricardo
 *
 */
public class CipherConfiguration implements Serializable {
	
	private String ciphersuite;
	private int keySize;
	private String keyValue;
	private String macAlgorithm;
	private int macKeySize;
	private String macKeyValue;

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

	public String getKeyValue() {
		return keyValue;
	}

	public void setKeyValue(String keyValue) {
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

	public String getMacKeyValue() {
		return macKeyValue;
	}

	public void setMacKeyValue(String macKeyValue) {
		this.macKeyValue = macKeyValue;
	}

	@Override
	public String toString() {
		return "CIPHERSUITE: " + this.ciphersuite + "\n" + "KEYSIZE: " + this.keySize + "\n" + "KEYVALUE: "
				+ this.keyValue + "\n" + "MAC: " + this.macAlgorithm + "\n" + "MACKEYSIZE: " + this.macKeySize + "\n"
				+ "MACKEYVALUE: " + this.macKeyValue;
	}

}
