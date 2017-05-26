package security;

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
	
	public CipherConfiguration(CipherConfiguration cipherConfig){
		this.ciphersuite = cipherConfig.getCiphersuite();
		this.keySize = cipherConfig.getKeySize();
		this.keyValue = cipherConfig.getKeyValue();
		this.macAlgorithm = cipherConfig.getMacAlgorithm();
		this.macKeySize = cipherConfig.getMacKeySize();
		this.macKeyValue = cipherConfig.getMacKeyValue();
	}
	
	public CipherConfiguration(String crypto){
		String[] keyvalues = crypto.split(" | ");
		this.ciphersuite = keyvalues[1].trim();
		this.keySize = Integer.parseInt(keyvalues[4].trim());
		this.keyValue = keyvalues[7].trim();
		this.macAlgorithm = keyvalues[10].trim();
		this.macKeySize = Integer.parseInt(keyvalues[13].trim());
		this.macKeyValue = keyvalues[16].trim();
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
	
	public String toSimpleStringFormat(){
		return "ciphersuite: " + this.ciphersuite + " | keysize: " + this.keySize + " | keyvalue: " + this.keyValue 
				+ " | mac: " + this.macAlgorithm + " | mackeysize: " + this.macKeySize + " | mackeyvalue: " + this.macKeyValue;
	}

}
