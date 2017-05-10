package application;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.swing.JOptionPane;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

public class MyMChatCliente extends MChatCliente {

	public MyMChatCliente() {
		super();
	}

	/**
	 * 
	 * @param username
	 * @param password
	 * @param roomName
	 * @param pbe
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws ClassNotFoundException
	 * @throws KeyManagementException 
	 */
	private static byte[] authenticateUser(String username, String password, String roomName, PBEConfiguration pbe)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, KeyManagementException {

		// hash password
		String hashedPassword = DigestHandler.hashPassword(password);
		byte[] hashedPasswordByte = Utils.toByteArray(hashedPassword);
		int sendedNonce = SecureRandom.getInstanceStrong().nextInt();
		IvParameterSpec generatedNonce = Utils.createCtrIvForAES(sendedNonce, new SecureRandom());

		//Concatenate the bytes of nonce and ash pass and only nonce and password go encrypted
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write( generatedNonce.getIV() );
		outputStream.write( hashedPasswordByte );
		
		byte messageByte[] = outputStream.toByteArray( );

		byte[] messageByteCipher = MessageCipherHandler.cipherMessageWithPBE(hashedPassword, pbe, messageByte);

		// configure the SSLContext with a TrustManager
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(new KeyManager[0], new TrustManager[] {new DefaultTrustManager()}, new SecureRandom());
        SSLContext.setDefault(ctx);
        
		String hostname = "localhost:9090";
		Client client = ClientBuilder.newBuilder()
									 .hostnameVerifier(new InsecureHostnameVerifier())
									 .build();

		URI baseURI = UriBuilder.fromUri("https://" + hostname + "/").build();
		WebTarget target = client.target(baseURI);
		
		// if password don't match it will receive error message
		Response encriptedRes = target.path("Authentication/" + username + "/" + roomName).request()
				.accept(MediaType.APPLICATION_OCTET_STREAM)
				.post(Entity.entity(messageByteCipher, MediaType.APPLICATION_OCTET_STREAM));

		// Não tenho a certeza
		byte[] encriptedFileCrypto = encriptedRes.readEntity(byte[].class);
		
		byte[] decriptedBytes = MessageCipherHandler.uncipherMessageWithPBE(hashedPassword, encriptedFileCrypto, pbe);
		
		ByteArrayInputStream inputStream = new ByteArrayInputStream( decriptedBytes );
		
		//get the iv bytes
		byte[] ivNumberBytes = new byte[4];
		inputStream.read(ivNumberBytes,0,4);
		byte[] ivParamenters = new byte[12];
		inputStream.read(ivParamenters, 0, 12);
		
		ByteBuffer numBuffer = ByteBuffer.wrap(ivNumberBytes);
		int newNonce = numBuffer.getInt();
		
		if(sendedNonce + 1 != newNonce)
			System.out.println("Message replying");
		
		byte[] decriptedCrypto = new byte[inputStream.available()];
		inputStream.read(decriptedCrypto, 0, inputStream.available());
		
		return decriptedCrypto;
	}

	/**
	 * Command-line invocation expecting three argument
	 * @param args
	 */
	public static void main(String[] args) {
		if ((args.length != 3) && (args.length != 4)) {
			System.err.println("Utilizar: MyMChatCliente " + "<nickusername> <grupo IPMulticast> <porto> { <ttl> }");
			System.err.println("       - TTL default = 1");
			System.exit(1);
		}

		String username = args[0];
		InetAddress group = null;
		int port = -1;
		int ttl = 1;

		try {
			group = InetAddress.getByName(args[1]);
		} catch (Throwable e) {
			System.err.println("Endereco de grupo multicast invalido: " + e.getMessage());
			System.exit(1);
		}

		if (!group.isMulticastAddress()) {
			System.err.println("Argumento Grupo '" + args[1] + "' nao e um end. IP multicast");
			System.exit(1);
		}

		try {
			port = Integer.parseInt(args[2]);
		} catch (NumberFormatException e) {
			System.err.println("Porto invalido: " + args[2]);
			System.exit(1);
		}

		if (args.length >= 4) {
			try {
				ttl = Integer.parseInt(args[3]);
			} catch (NumberFormatException e) {
				System.err.println("TTL invalido: " + args[3]);
				System.exit(1);
			}
		}

		try {
			MChatCliente frame = new MyMChatCliente();
			frame.setSize(800, 300);
			frame.setVisible(true);

			String password = JOptionPane.showInputDialog(frame, "What is your password?", null);
			
			frame.join(username, group, port, ttl);

			// call the above method to send the request to the server
			authenticateUser(username, password, group.getHostAddress(),
					FileHandler.readPBEncryptionFile("configs/" + group.getHostAddress() + ".pbe"));

		} catch (Throwable e) {
			e.printStackTrace();
			System.err.println("Erro ao iniciar a frame: " + e.getClass().getName() + ": " + e.getMessage());
			System.exit(1);
		}
	}

	static public class InsecureHostnameVerifier implements HostnameVerifier {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	}
	
	private static class DefaultTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}
