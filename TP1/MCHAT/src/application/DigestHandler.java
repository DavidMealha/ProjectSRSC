package application;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class DigestHandler {

	public static String hashPassword(String password) 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		
		MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");	
		hash.update(password.getBytes());
		byte[] hashedPassword = hash.digest();
	
		System.out.println(Utils.toHex(hashedPassword));
		return Utils.toHex(hashedPassword);
	}
	
	//code superfluos, this is to be made on the server side
	public static boolean validatePassword(String password) throws NoSuchAlgorithmException, NoSuchProviderException {
		String hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
		System.out.println(hash.equals(hashPassword(password)));
		return hash.equals(hashPassword(password));
	}
	
	
	
}
