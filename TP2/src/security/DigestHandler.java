package security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import helpers.Utils;

/**
 * Class to hash the password inserted by the user.
 * 
 * @author David, Ricardo
 *
 */
public class DigestHandler {

	/**
	 * 
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static String hashPassword(String password) 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		
		MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");	
		hash.update(password.getBytes());
		byte[] hashedPassword = hash.digest();

		return Utils.toHex(hashedPassword);
	}
	
	/**
	 * 
	 * @param algorithm
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static String hashPassword(String algorithm, String password) 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		
		MessageDigest hash = MessageDigest.getInstance(algorithm, "BC");	
		hash.update(password.getBytes());
		byte[] hashedPassword = hash.digest();

		return Utils.toHex(hashedPassword);
	}

	/**
	 * 
	 * @param algorithm
	 * @param content
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static byte[] hashWithSHA(String algorithm, byte[] content) throws NoSuchAlgorithmException, NoSuchProviderException{
		MessageDigest hash = MessageDigest.getInstance(algorithm, "BC");
		return hash.digest(content);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException{
		if(args.length < 1){
			System.out.println("Insert password that you wish to hash and the algorithm!");
			System.out.println("e.g: password SHA-256");
		}
		System.out.println(hashPassword(args[0], args[1]));
	}
}
