package filegenerator;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyGenerator {

	/**
	 * Creates a random salt with 64/128/256 bits
	 * 
	 * @param nrBytes
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] generateSalt(int nrBytes) throws NoSuchAlgorithmException {
		byte[] salt = new byte[nrBytes];
		SecureRandom.getInstanceStrong().nextBytes(salt);
		return salt;
	}
}
