package security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


import auxiliaryClasses.Utils;

public class AshDigest {

	//only needed here for user file generation
	public static String ashPassword(String password) throws NoSuchAlgorithmException, NoSuchProviderException{
		MessageDigest   hash = MessageDigest.getInstance("SHA3-224", "BC");        
        hash.update(Utils.toByteArray(password));
        
        return Utils.toString(hash.digest());
	}
}
