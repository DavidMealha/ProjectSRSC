package application;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.swing.JOptionPane;

public class MyMChatCliente extends MChatCliente {
	
	public MyMChatCliente() { super(); }
	
	private static void authenticateUser(String username, String password) 
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException {

		//hash password
		String hashedPassword = DigestHandler.hashPassword(password);

//		URL url = new URL("http://localhost:9090/authentication");
//			
//		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
//		
//		conn.setDoOutput(true);
//		conn.setRequestMethod("POST");
//		conn.setRequestProperty("Content-Type", "application/json");
//		
//		String input = "{\"username\":" + username + ",\"password\":\"" + hashedPassword + "\"}";
//		
//		OutputStream os = conn.getOutputStream();
//		os.write(input.getBytes());
//		os.flush();
//		
//		if (conn.getResponseCode() != HttpURLConnection.HTTP_CREATED) {
//			throw new RuntimeException("Failed : HTTP error code : "
//				+ conn.getResponseCode());
//		}
//		
//		BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
//		
//		String output;
//		System.out.println("Output from Server .... \n");
//		while ((output = br.readLine()) != null) {
//			System.out.println(output);
//		}

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
			
			// String password = JOptionPane.showInputDialog(frame, "What is your password?", null);
			
			// call the REST Server to authenticate the user
			// authenticateUser(username, password);
			
		} catch (Throwable e) {
			System.err.println("Erro ao iniciar a frame: " + e.getClass().getName() + ": " + e.getMessage());
			System.exit(1);
		}
	}
}
