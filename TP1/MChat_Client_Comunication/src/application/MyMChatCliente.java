package application;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.swing.JOptionPane;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
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

	private static void authenticateUser(String username, String password, String roomName, PBEConfiguration pbe)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {

		// hash password
		String hashedPassword = DigestHandler.hashPassword(password);

		// only nonce and password go encrypted
		String message = pbe.getCounter() + " " + hashedPassword;
		byte[] messageByte = MessageCipherHandler.cipherMessageWithPBE(hashedPassword, pbe, Utils.toByteArray(message));

		String hostname = "localhost:9090";
		Client client = ClientBuilder.newBuilder().hostnameVerifier(new InsecureHostnameVerifier()).build();

		URI baseURI = UriBuilder.fromUri("https://" + hostname + "/").build();
		WebTarget target = client.target(baseURI);

		// if password don't match it will receive error message
		Response encriptedRes = target.path("Authentication/" + username + "/" + roomName).request()
				.accept(MediaType.APPLICATION_OCTET_STREAM)
				.post(Entity.entity(messageByte, MediaType.APPLICATION_OCTET_STREAM));

		// Não tenho a certeza
		byte[] encriptedFileCrypto = encriptedRes.readEntity(byte[].class);
	}

	// Command-line invocation expecting three arguments
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

			frame.join(username, group, port, ttl);

			String password = JOptionPane.showInputDialog(frame, "What is your password?", null);

			// call the above method to send the request to the server
			authenticateUser(username, password, group.getHostAddress(),
					FileHandler.readPBEncryptionFile("configs/" + group.getHostAddress() + ".pbe"));

		} catch (Throwable e) {
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
}
