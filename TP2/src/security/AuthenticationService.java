//package security;
//
//import java.io.ByteArrayInputStream;
//import java.io.ByteArrayOutputStream;
//import java.io.IOException;
//import java.net.URI;
//import java.nio.ByteBuffer;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.KeyManagementException;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.SecureRandom;
//import java.security.spec.InvalidKeySpecException;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.spec.IvParameterSpec;
//import javax.net.ssl.KeyManager;
//import javax.net.ssl.SSLContext;
//import javax.net.ssl.TrustManager;
//import javax.ws.rs.client.Client;
//import javax.ws.rs.client.ClientBuilder;
//import javax.ws.rs.client.Entity;
//import javax.ws.rs.client.WebTarget;
//import javax.ws.rs.core.MediaType;
//import javax.ws.rs.core.Response;
//import javax.ws.rs.core.UriBuilder;
//
//import helpers.FileHandler;
//import helpers.TLSConfiguration;
//import helpers.Utils;
//
//public class AuthenticationService {
//
//	private static final String CONFIGS_PATH = "configs/";
//	private static final String PBE_EXTENSION = ".pbe";
//	private static final String TLS_CONFIG = "configs/tls.config";
//
//	public static byte[] authenticateUser(String username, String userPassword, String multicastAddress)
//			throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException,
//			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException,
//			IllegalBlockSizeException, BadPaddingException, KeyManagementException, ClassNotFoundException {
//		// message format: username || IPMULTICASH || NONCE || H(PWD)
//
//		// 1st step - hash the password
//		String hashedPassword = hashUserPassword(userPassword);
//		byte[] hashedUserPassword = Utils.toByteArray(hashedPassword);
//
//		// 2nd step - generate nonce
//		int sentNonce = generateNonce();
//
//		// 3nd step - Concatenate the bytes of nonce and ash pass and only nonce
//		// and password go encrypted
//		byte[] clearPayload = createPayload(username, hashedUserPassword, sentNonce, multicastAddress);
//
//		// !!!not needed for tls, already encrypts the data sent..!!!
//		PBEConfiguration pbe = FileHandler.readPBEncryptionFile(CONFIGS_PATH + multicastAddress + PBE_EXTENSION);
//
//		// !!!not needed for tls, already encrypts the data sent..!!!
//		// 4th step - cipher message with pbe configuration
//		byte[] messageByteCipher = MessageCipherHandler.cipherMessageWithPBE(hashedPassword, pbe, clearPayload);
//
//		// 5th step - read the tls configuration file
//		TLSConfiguration tlsConfig = FileHandler.readTLSConfiguration(TLS_CONFIG);
//
//		// 6th step - connect to the server with SSL
//		SSLContext ctx = SSLContext.getInstance("TLSv1.2");
//		ctx.init(new KeyManager[0], new TrustManager[] { new InsecureTrustManager() }, new SecureRandom());
//		SSLContext.setDefault(ctx);
//
//		String hostname = "localhost:9090";
//		Client client = ClientBuilder.newBuilder().hostnameVerifier(new InsecureHostnameVerifier()).sslContext(ctx)
//				.build();
//
//		URI baseURI = UriBuilder.fromUri("https://" + hostname + "/").build();
//		WebTarget target = client.target(baseURI);
//
//		// if password don't match it will receive error message
//		Response encriptedRes = target.path("Authentication/" + username + "/" + multicastAddress).request()
//				.accept(MediaType.APPLICATION_OCTET_STREAM)
//				.post(Entity.entity(messageByteCipher, MediaType.APPLICATION_OCTET_STREAM));
//
//		System.out.println(encriptedRes.getStatus());
//
//		// Não tenho a certeza
//		byte[] encriptedFileCrypto = encriptedRes.readEntity(byte[].class);
//
//		byte[] decriptedBytes = MessageCipherHandler.uncipherMessageWithPBE(hashedPassword, encriptedFileCrypto, pbe);
//
//		ByteArrayInputStream inputStream = new ByteArrayInputStream(decriptedBytes);
//
//		// get the iv bytes
//		byte[] ivNumberBytes = new byte[4];
//		inputStream.read(ivNumberBytes, 0, 4);
//		byte[] ivParamenters = new byte[12];
//		inputStream.read(ivParamenters, 0, 12);
//
//		ByteBuffer numBuffer = ByteBuffer.wrap(ivNumberBytes);
//		int newNonce = numBuffer.getInt();
//
//		if (sentNonce + 1 != newNonce)
//			System.out.println("Message replying");
//
//		byte[] decriptedCrypto = new byte[inputStream.available()];
//		inputStream.read(decriptedCrypto, 0, inputStream.available());
//
//		return decriptedCrypto;
//	}
//
//	/**
//	 * 
//	 * @param userPassword
//	 * @return
//	 * @throws NoSuchProviderException
//	 * @throws NoSuchAlgorithmException
//	 */
//	private static String hashUserPassword(String userPassword)
//			throws NoSuchAlgorithmException, NoSuchProviderException {
//		return DigestHandler.hashPassword(userPassword);
//	}
//
//	/**
//	 * 
//	 * @return
//	 * @throws NoSuchAlgorithmException
//	 */
//	private static int generateNonce() throws NoSuchAlgorithmException {
//		return SecureRandom.getInstanceStrong().nextInt();
//		// IvParameterSpec generatedNonce = Utils.createCtrIvForAES(sentNonce,
//		// new SecureRandom());
//		// return generatedNonce.getIV();
//	}
//
//	/**
//	 * 
//	 * @param username
//	 * @param hashedPassword
//	 * @param sentNonce
//	 * @param multicastAddress
//	 * @return
//	 * @throws IOException
//	 */
//	private static byte[] createPayload(String username, byte[] hashedPassword, int sentNonce, String multicastAddress)
//			throws IOException {
//		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//		outputStream.write(username.getBytes());
//		// multicast address
//		outputStream.write(multicastAddress.getBytes());
//		outputStream.write(sentNonce);
//		outputStream.write(hashedPassword);
//
//		// (username || IPMULTICASH || NONCE || H(PWD))
//		return outputStream.toByteArray();
//	}
//
//	private static void configureSSLContext() {
//
//	}
//}
