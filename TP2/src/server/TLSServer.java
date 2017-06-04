package server;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.*;

import helpers.FileHandler;
import helpers.ServerFileHandler;
import helpers.TLSConfiguration;
import security.CipherConfiguration;
import security.CipherHandler;
import security.PBEConfiguration;

public class TLSServer {

	private static final String SERVER_TLS_CONFIGURATION = "server.tls.config";
	private static final String CERTIFICATES_PATH = "certificates/";
	private static final String KEYSTORE_EXTENSION = ".keystore";
	private static final String SERVER_FILES_PATH = "database/";
	
	/**
	 * 
	 * @param keystorePassword
	 * @param entryPassword
	 * @param port
	 */
	public static void main(String[] args) {
		if (args.length != 4) {
			System.out.println("4 Arguments required: keystorePassword entryPassword serverPbePassword port");
			System.exit(0);
		}

		System.out.println("Server running!");
		
		while(true){

			//create trust manager
			TrustManager[] trustedCerts = new TrustManager[] {new InsecureTrustManager()};
			
			try {
				// read the tls configuration file
				TLSConfiguration tlsConfig = FileHandler.readTLSConfiguration(SERVER_FILES_PATH + SERVER_TLS_CONFIGURATION);
				
				System.setProperty("javax.net.ssl.trustStore", CERTIFICATES_PATH + tlsConfig.getTruststoreFilename());
				System.setProperty("javax.net.ssl.trustStorePassword", "clientTrustedStore");
				
				char[] keystorePassword = args[0].toCharArray(); // password da keystore
				char[] entryPassword = args[1].toCharArray(); // password entry
				int port = Integer.parseInt(args[3]); //port
				String serverPBEPassword = args[2];
				
				SSLSocket c = null;
				SSLServerSocket s = null;
				
				if (tlsConfig.getAuthenticationType().equals("SERVIDOR") || 
					tlsConfig.getAuthenticationType().equals("CLIENTE-SERVIDOR")) {
					
					// load server keystore
					KeyStore ks = KeyStore.getInstance("JKS");
					ks.load(new FileInputStream(CERTIFICATES_PATH + tlsConfig.getPrivateKeyStoreFilename() + KEYSTORE_EXTENSION), keystorePassword);
		
					KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
					kmf.init(ks, entryPassword);
					
					//get the version from the config file
					SSLContext sc = SSLContext.getInstance(tlsConfig.getVersion());
					sc.init(kmf.getKeyManagers(), trustedCerts, null);
					//sc.init(kmf.getKeyManagers(), null, null);
					
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
					SSLContext sc = SSLContext.getInstance(tlsConfig.getVersion());
					sc.init(null, trustedCerts, null);
					
					SSLServerSocketFactory ssf = sc.getServerSocketFactory();
					s = (SSLServerSocket) ssf.createServerSocket(port);
					
					s.setEnabledProtocols(new String[] { tlsConfig.getVersion() });
					s.setEnabledCipherSuites(new String[] { tlsConfig.getCiphersuite() });
					
					s.setUseClientMode(true);
					
					c = (SSLSocket) s.accept();
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
				
				String authResult = validateAuthentication(hashedPwdReceived, multicastAddress, username);
				
				w.write(authResult.toCharArray(), 0, authResult.length());
				w.newLine();
				w.flush();
				
				if(authResult.equals("true")){
					String crypto = cipherClientCryptoWithPBE(multicastAddress, hashedPwdReceived, serverPBEPassword);
					w.write(crypto, 0, crypto.length());
					w.newLine();
					w.flush();
				}
				
				//closing connection and data stream
				w.close();
				r.close();
				c.close();
				s.close();
			} catch (Exception e) {
				//e.printStackTrace();
				System.err.println(e.toString());
				System.exit(0);
			}
		}
	}
	
	/**
	 * 
	 * @param hashedPasswordReceived
	 * @param multicastAddress
	 * @param username
	 * @return
	 */
	private static String validateAuthentication(String hashedPasswordReceived, String multicastAddress, String username){
		//compares password stored in the server
		String storedHashedPassword = ServerFileHandler.getUserPasswordFromFile(username);
		
		if(storedHashedPassword.equals(hashedPasswordReceived)){
			//check if can access that room
			if(ServerFileHandler.isUserAllowed(multicastAddress, username)){
				return "true";
			} else {
				return "Access Control Failed";
			}
		} else {
			return "Authentication Failed";
		}
	}
	
	/**
	 * ler ficheiro .crypto do servidor, que estava encriptado com as credenciais do servidor
	 * encriptar com esquema PBE com a password do utilizador
	 * enviar em String ou char[] o .crypto encriptado com PBE para o utilizador
	 * @param multicastAddress
	 * @param userPassword
	 * @param serverPbePassword
	 * @throws IOException
	 */
	private static String cipherClientCryptoWithPBE(String multicastAddress, String userPassword, String serverPbePassword) throws IOException{
		CipherConfiguration cipherConfig = null;
		
		try {
			cipherConfig = new CipherConfiguration(CipherHandler.uncipherFileWithPBE(serverPbePassword, SERVER_FILES_PATH +  multicastAddress));
		} 
		catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| ClassNotFoundException e) {
			System.out.println("Failed to parse the ciphersuite." + e.getMessage());
		}

		return cipherConfig.toSimpleStringFormat();
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