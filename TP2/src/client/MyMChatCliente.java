package client;

import java.io.IOException;
import java.net.InetAddress;
import javax.swing.JOptionPane;

import security.CipherConfiguration;
import security.PBEConfiguration;

public class MyMChatCliente extends MChatCliente {

	private CipherConfiguration cipherConfiguration;
	
	public CipherConfiguration getCipherConfiguration() {
		return cipherConfiguration;
	}

	public void setCipherConfiguration(CipherConfiguration cipherConfiguration) {
		this.cipherConfiguration = cipherConfiguration;
	}

	/**
	 * Command-line invocation expecting three argument
	 * @param args
	 */
	public static void main(String[] args) {
		if ((args.length != 5) && (args.length != 6)) {
			System.err.println("Utilizar: MyMChatCliente " + "<nickusername> <grupo IPMulticast> <porto> <keystorePassword> <keystoreEntryPassword> { <ttl> }");
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
		
		String keystorePassword = args[3];
		String keystoreEntryPassword = args[4];

		if (args.length >= 6) {
			try {
				ttl = Integer.parseInt(args[5]);
			} catch (NumberFormatException e) {
				System.err.println("TTL invalido: " + args[3]);
				System.exit(1);
			}
		}

		try {
			MyMChatCliente frame = new MyMChatCliente();
			
			//ask for the password before showing the chat
			String password = JOptionPane.showInputDialog(frame, "What is your password?", null);
			
			//clientKeyStorePassword
			TLSClient tlsClient = new TLSClient(username, password, group.getHostAddress(), keystorePassword, keystoreEntryPassword, "localhost", 4443);
			tlsClient.run();
			
			if(tlsClient.getAuthenticationSuccess()){
				System.out.println("Autenticação bem sucedida!");
				
				frame.setSize(800, 300);
				frame.setVisible(true);
				frame.join(username, group, port, ttl, tlsClient.getCrypto());				
			}else{
				System.err.println("Autenticação falhada!");
				System.exit(1);
			}

		} catch (Throwable e) {
			e.printStackTrace();
			System.err.println("Erro ao iniciar a frame: " + e.getClass().getName() + ": " + e.getMessage());
			System.exit(1);
		}
	}
	
	public void join(String username, InetAddress group, int port, int ttl, CipherConfiguration cipherConfiguration) throws IOException {
		setTitle("CHAT MulticastIP " + username + "@" + group.getHostAddress() + ":" + port + " [TTL=" + ttl + "]");

		// Criar sessao de chat multicast
		chat = new MyMulticastChat(username, group, port, ttl, this, cipherConfiguration);
	}
}
