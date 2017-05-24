package client;

import java.util.*;
import java.io.*;
import java.net.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.*;

import helpers.FileHandler;
import helpers.TLSConfiguration;
import security.DigestHandler;

public class TLSClient {

	private static final String CONFIGS_PATH = "configs/";
	private static final String TLS_CONFIGURATION_EXTENSION = ".tls.config";
	private static final String CERTIFICATES_PATH = "certificates/";
	private static final String KEYSTORE_EXTENSION = ".keystore";

	private boolean authenticationResult = false;

	private String username;
	private String hashedPassword;
	private String multicastAddress;
	private char[] clientKeyStorePassword;
	private char[] clientEntryPassword;
	
	private String serverAddress;
	private int serverPort;

	public TLSClient(String username, String clearPassword, String multicastAddress, String clientKeyStorePassword, String clientEntryPassword, String serverAddress, int serverPort) {
		this.username = username;
		this.multicastAddress = multicastAddress;
		this.clientKeyStorePassword = clientKeyStorePassword.toCharArray();
		this.clientEntryPassword = clientEntryPassword.toCharArray();

		try {
			this.hashedPassword = DigestHandler.hashPassword(clearPassword);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
		
		this.serverAddress = serverAddress;
		this.serverPort = serverPort;
	}
	
	public boolean getAuthenticationSuccess(){
		return this.authenticationResult;
	}

	/**
	 * Connects to the server to authenticate the user
	 */
	public void run() {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

		// read the tls configuration file
		TLSConfiguration tlsConfig = FileHandler.readTLSConfiguration(CONFIGS_PATH + this.username + TLS_CONFIGURATION_EXTENSION);

		System.setProperty("javax.net.ssl.trustStore", CERTIFICATES_PATH + tlsConfig.getTruststoreFilename());
		System.setProperty("javax.net.ssl.trustStorePassword", "clientTrustedStore");

		SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLContext ctx;
		SSLSocket c = null;
		
		KeyManagerFactory kmf;
		KeyStore ks;
		
		try {

			if (tlsConfig.getAuthenticationType().equals("SERVIDOR")) 
			{
				//might not be needed...
			} 
			else if(tlsConfig.getAuthenticationType().equals("CLIENTE-SERVIDOR") || 
					tlsConfig.getAuthenticationType().equals("CLIENTE"))
			{
				// se o cliente tambem tem de se autenticar, vai ter de obter a
				// keystore, tal como o servidor, por isso é que recebe a keystore password
				try {
					ctx = SSLContext.getInstance(tlsConfig.getVersion());
					
					ks = KeyStore.getInstance("JKS");
					ks.load(new FileInputStream(CERTIFICATES_PATH + tlsConfig.getPrivateKeyStoreFilename() + KEYSTORE_EXTENSION), this.clientKeyStorePassword);
					
					kmf = KeyManagerFactory.getInstance("SunX509");
					kmf.init(ks, this.clientEntryPassword);
					
					ctx.init(kmf.getKeyManagers(), null, null);
					f = ctx.getSocketFactory();
					
				} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException | KeyManagementException e) {
					e.printStackTrace();
				}
			}
			
			c = (SSLSocket) f.createSocket("localhost", 4443);
			
			c.setEnabledProtocols(new String[] { tlsConfig.getVersion() });
			c.setEnabledCipherSuites(new String[] { tlsConfig.getCiphersuite() });
			
		
			if (tlsConfig.getAuthenticationType().equals("SERVIDOR") ||
				tlsConfig.getAuthenticationType().equals("CLIENTE-SERVIDOR")) {
				
				// ter que ter o startHandshake depois da parameterização
				c.startHandshake();
			}


			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
			
			System.out.println(this.hashedPassword);
			System.out.println(r.readLine());
			
			// write username
			w.write(username);
			w.newLine();

			// write hashed password
			w.write(hashedPassword);
			w.newLine();

			// write multicast address for access control
			w.write(multicastAddress);
			w.newLine();

			// send it all to the server
			w.flush();

			String authenticationResult = r.readLine();
			
			String m = "";
			while ((m = r.readLine()) != null) {
				System.out.println(m);
				m = in.readLine();
			}
			
			System.out.println(authenticationResult);
			
			if(authenticationResult.equals("true")){
				this.authenticationResult = true;
			}
			//returns true if true
			//Boolean.parseBoolean(authenticationResult);
			
			w.close();
			r.close();
			c.close();
		} catch (IOException e) {
			e.printStackTrace();
			// System.err.println(e.toString());
		}
	}

	private static void printSocketInfo(SSLSocket s) {

		System.out.println("\n------------------------------------------------------\n");
		System.out.println("Socket class: " + s.getClass());
		System.out.println("   Remote address = " + s.getInetAddress().toString());
		System.out.println("   Remote port = " + s.getPort());
		System.out.println("   Local socket address = " + s.getLocalSocketAddress().toString());
		System.out.println("   Local address = " + s.getLocalAddress().toString());
		System.out.println("   Local port = " + s.getLocalPort());
		System.out.println("   Need client authentication = " + s.getNeedClientAuth());
		System.out.println("   Client mode = " + s.getUseClientMode());
		System.out.println("\n------------------------------------------------------\n");

		System.out.println("   Enabled Protocols = " + Arrays.asList(s.getEnabledProtocols()));
		System.out.println("\n------------------------------------------------------\n");

		System.out.println("   Client Supprted Ciphersuites = " + Arrays.asList(s.getSupportedCipherSuites()));
		System.out.println("\n------------------------------------------------------\n");
		System.out.println("   Enabled Ciphersuites = " + Arrays.asList(s.getEnabledCipherSuites()));

		System.out.println("\n------------------------------------------------------\n");

		SSLSession ss = s.getSession();

		System.out.println("   Peer Host = " + ss.getPeerHost());
		System.out.println("   Peer Port = " + ss.getPeerPort());

		System.out.println("   Protocol = " + ss.getProtocol());
		System.out.println("   Cipher suite = " + ss.getCipherSuite());

		System.out.println("   Packet Buffer Size = " + ss.getPacketBufferSize());

		System.out.println("\n------------------------------------------------------\n");

	}
}