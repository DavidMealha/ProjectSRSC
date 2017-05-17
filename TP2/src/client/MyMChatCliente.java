package client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.swing.JOptionPane;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import helpers.FileHandler;
import helpers.Utils;
import security.AuthenticationService;
import security.DigestHandler;
import security.InsecureHostnameVerifier;
import security.InsecureTrustManager;
import security.MessageCipherHandler;
import security.PBEConfiguration;

public class MyMChatCliente extends MChatCliente {

	public static final String baseUri = "https://localhost:9090";
	private Client client;
	private WebTarget target;
	
	public MyMChatCliente() {
		super();
		client = ClientBuilder.newClient();
        target = client.target(baseUri);
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

			//send the request to the server to authenticate the user
			AuthenticationService.authenticateUser(username, password, group.getHostAddress());

		} catch (Throwable e) {
			e.printStackTrace();
			System.err.println("Erro ao iniciar a frame: " + e.getClass().getName() + ": " + e.getMessage());
			System.exit(1);
		}
	}
}
