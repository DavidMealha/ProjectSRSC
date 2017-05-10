package filegenerator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import application.FileHandler;
import application.PBEConfiguration;
import application.Utils;

/**
 * This class generates the .crypto file giving a user password and with the existing pbe file
 * It is required a .txt with the original .crypto information
 * 
 * @authors Ricardo 
 *
 */

public class DynamicPBEncryptor { 
	
	
	private static final String LOGFILESDIR = "configs/";
	
	public static void main(String[] args) throws Exception {
		
		if (args.length != 2) {
		    System.err.println("------> Wrong number of arguments (Password, FileName)");
		    System.exit(-1);
		}
		
		//Parameter initialization
		char[] password = args[0].toCharArray();
		
		PBEConfiguration pbeParam;
		String pbeFileName = LOGFILESDIR + args[1] + ".pbe";
		pbeParam = FileHandler.readPBEncryptionFile(pbeFileName);	
		
		System.out.println(pbeParam.getAlgorithm());
		
		// fetch data file
		File cryptaDataFile = new File(LOGFILESDIR + args[1] + ".txt");
		FileInputStream inputDataFile = new FileInputStream(cryptaDataFile);
		byte data[] = new byte[(int)cryptaDataFile.length()];
		inputDataFile.read(data);
		
		// Initialization of new crypto file
		String newCryptoName = LOGFILESDIR + args[1] + ".crypto";
		FileOutputStream cryptoFile = new FileOutputStream(newCryptoName);
		
		// Key initialization
		PBEKeySpec pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance( pbeParam.getAlgorithm() ,"BC");
        Key sKey= keyFact.generateSecret(pbeSpec);

        // Cipher 
        Cipher cEnc = Cipher.getInstance( pbeParam.getAlgorithm(),"BC");
        System.out.println(Utils.toHex(sKey.getEncoded()));
        cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(pbeParam.getSalt().getBytes(), pbeParam.getCounter()));

        byte[] encryptedOut = cEnc.doFinal(data);
        
        cryptoFile.write(encryptedOut);
        System.out.println("------> File "+ newCryptoName + " created");
	}

}
