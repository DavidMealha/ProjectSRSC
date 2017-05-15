package security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Class to hash the password inserted by the user.
 * 
 * @author David, Ricardo
 *
 */
public class DigestHandler {

	public static String hashPassword(String password) 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		
		MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");	
		hash.update(password.getBytes());
		byte[] hashedPassword = hash.digest();

		return Utils.toHex(hashedPassword);
	}

}
