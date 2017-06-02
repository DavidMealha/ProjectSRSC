package diffiehellman;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.HashMap;

import helpers.FileHandler;
import helpers.Utils;

public class MyDigitalSignature {

	private String keyAlgorithm;;
	private int keySize;
	private String signatureAlgorithm;
	
	private KeyPair myPair;
	
	private static final String DIGITAL_SIGNATURE_CONFIG_PATH = "configs/digitalSignatures.config"; 
	
	public MyDigitalSignature(){
		HashMap<String, String> fileContent = FileHandler.getKeyValuesFromFile(DIGITAL_SIGNATURE_CONFIG_PATH);
		
		this.keyAlgorithm = fileContent.get("KEYALG");
		this.keySize = Integer.parseInt(fileContent.get("KEYSIZE"));
		this.signatureAlgorithm = fileContent.get("SIGNALG");
	}
	
	/**
	 * 
	 * @param content
	 * @return
	 * @throws Exception
	 */
	public String signContent(byte[] content) throws Exception{
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(this.keyAlgorithm, "BC");
        keyGen.initialize(this.keySize, new SecureRandom());
        
        this.myPair = keyGen.generateKeyPair();
        
        Signature signature = Signature.getInstance(this.signatureAlgorithm, "BC");
        signature.initSign(this.myPair.getPrivate(), UtilsDH.createFixedRandom());
        signature.update(content);
        
        return Utils.toHex(signature.sign());
	}

	public String getMyPublicKeyHex() {
		return Utils.toHex(myPair.getPublic().getEncoded());
	}
	
}
