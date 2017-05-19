package server;

import java.io.*;
import java.security.*;
import javax.net.ssl.*;

import helpers.FileHandler;
import helpers.ServerFileHandler;
import helpers.TLSConfiguration;

public class TLSServer {

	private static final String SERVER_TLS_CONFIGURATION = "configs/server.tls.config";
	private static final String CERTIFICATES_PATH = "certificates/";
	private static final String KEYSTORE_EXTENSION = ".keystore";
	
	/**
	 * 
	 * @param keystorePassword
	 * @param entryPassword
	 * @param port
	 */
	public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println("3 Arguments required: keystorePassword entryPassword port");
			System.exit(0);
		}

		System.out.println("Server running!");
		
		while(true){

			try {
				// read the tls configuration file
				TLSConfiguration tlsConfig = FileHandler.readTLSConfiguration(SERVER_TLS_CONFIGURATION);
		
				char[] keystorePassword = args[0].toCharArray(); // password da keystore
				char[] entryPassword = args[1].toCharArray(); // password entry
				int port = Integer.parseInt(args[2]); //port
				
				SSLSocket c = null;
				SSLServerSocket s = null;
				
				if (tlsConfig.getAuthenticationType().equals("SERVIDOR")
						|| tlsConfig.getAuthenticationType().equals("CLIENTE-SERVIDOR")) {
					
					// load server keystore
					KeyStore ks = KeyStore.getInstance("JKS");
					ks.load(new FileInputStream(CERTIFICATES_PATH + tlsConfig.getPrivateKeyStoreFilename() + KEYSTORE_EXTENSION), keystorePassword);
		
					KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
					kmf.init(ks, entryPassword);
		
					//get the version from the config file
					SSLContext sc = SSLContext.getInstance(tlsConfig.getVersion());
					sc.init(kmf.getKeyManagers(), null, null);
					
					SSLServerSocketFactory ssf = sc.getServerSocketFactory();
					s = (SSLServerSocket) ssf.createServerSocket(port);
		
					if (tlsConfig.getAuthenticationType().equals("SERVIDOR")) {
						s.setNeedClientAuth(false);
					} else {
						s.setNeedClientAuth(true);
					}
		
					s.setEnabledProtocols(new String[] { tlsConfig.getVersion() });
					s.setEnabledCipherSuites(new String[] { tlsConfig.getCiphersuite() });
		
					c = (SSLSocket) s.accept();
				} 
				else 
				{
					// s condiciona o fluxo se é inicializado pelo cliente ou o
					// servidor
					// como o cliente fosse o servidor fosse e assim autentica-se e
					// o servidor
		
					// SSLServerSocket passa para o cliente, ou simplesmente no
					// SSLSocket o servidor é que faz o startHandshake?
					c.startHandshake();
				}
		
				BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
				BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
		
				
				// Service from this server ...
				String m = "Welcome!";
				w.write(m, 0, m.length());
				w.newLine();
				w.flush();
				
				String username = r.readLine();
				System.out.println("User trying to authenticate: " + username);
				
				String hashedPwdReceived = r.readLine();
				System.out.println("With this password: " + hashedPwdReceived);
				
				String multicastAddress = r.readLine();
				System.out.println("Trying to access the address : " + multicastAddress);
				
				//compares password stored in the server
				String storedHashedPassword = ServerFileHandler.getUserPasswordFromFile(username);
				
				String authResult = "";
				
				if(storedHashedPassword.equals(hashedPwdReceived)){
					
					//check if can access that room
					if(ServerFileHandler.isUserAllowed(multicastAddress, username)){
						authResult = "true";
					}
					else
					{
						authResult = "Access Control Failed";
					}
				}
				else
				{
					authResult = "Authentication Failed";
				}
				
				w.write(authResult.toCharArray(), 0, authResult.length());
				w.newLine();
				w.flush();
				
				//closing connection and data stream
				w.close();
				r.close();
				c.close();
				s.close();
			} catch (Exception e) {
				e.printStackTrace();
				//System.err.println(e.toString());
			}
			
		}
	}

	private static void printSocketInfo(SSLSocket s) {
		System.out.println("Socket class: " + s.getClass());
		System.out.println("   Remote address = " + s.getInetAddress().toString());
		System.out.println("   Remote port = " + s.getPort());
		System.out.println("   Local socket address = " + s.getLocalSocketAddress().toString());
		System.out.println("   Local address = " + s.getLocalAddress().toString());
		System.out.println("   Local port = " + s.getLocalPort());
		System.out.println("   Need client authentication = " + s.getNeedClientAuth());
		SSLSession ss = s.getSession();
		System.out.println("   Cipher suite = " + ss.getCipherSuite());
		System.out.println("   Protocol = " + ss.getProtocol());
	}

	private static void printServerSocketInfo(SSLServerSocket s) {
		System.out.println("Server socket class: " + s.getClass());
		System.out.println("   Socker address = " + s.getInetAddress().toString());
		System.out.println("   Socker port = " + s.getLocalPort());
		System.out.println("   Need client authentication = " + s.getNeedClientAuth());
		System.out.println("   Want client authentication = " + s.getWantClientAuth());
		System.out.println("   Use client mode = " + s.getUseClientMode());
	}
}