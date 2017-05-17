package helpers;

public class TLSConfiguration {
	
	private String version;
	private String authenticationType;
	private String ciphersuite;
	private String privateKeyStoreFilename;
	private String truststoreFilename;
	
	public TLSConfiguration(){}
	
	public TLSConfiguration(String version, String authenticationType, String ciphersuite, String privateKeyStoreFilename, String truststoreFilename) {
		this.version = version;
		this.authenticationType = authenticationType;
		this.ciphersuite = ciphersuite;
		this.privateKeyStoreFilename = privateKeyStoreFilename;
		this.truststoreFilename = truststoreFilename;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getAuthenticationType() {
		return authenticationType;
	}

	public void setAuthenticationType(String authenticationType) {
		this.authenticationType = authenticationType;
	}

	public String getCiphersuite() {
		return ciphersuite;
	}

	public void setCiphersuite(String ciphersuite) {
		this.ciphersuite = ciphersuite;
	}

	public String getPrivateKeyStoreFilename() {
		return privateKeyStoreFilename;
	}

	public void setPrivateKeyStoreFilename(String privateKeyStoreFilename) {
		this.privateKeyStoreFilename = privateKeyStoreFilename;
	}

	public String getTruststoreFilename() {
		return truststoreFilename;
	}

	public void setTruststoreFilename(String truststoreFilename) {
		this.truststoreFilename = truststoreFilename;
	}
	
	
}
