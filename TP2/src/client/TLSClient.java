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
import security.CipherConfiguration;
import security.CipherHandler;
import security.DigestHandler;
import security.PBEConfiguration;
import server.InsecureTrustManager;

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

	private CipherConfiguration crypto;

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
	
	public void setCipherConfiguration(String crypto){
		this.crypto = new CipherConfiguration(crypto);
	}

	public CipherConfiguration getCrypto() {
		return crypto;
	}

	public void setCrypto(CipherConfiguration crypto) {
		this.crypto = crypto;
	}

	/**
	 * Connects to the server to authenticate the user
	 */
	public void run() {
		TLSConfiguration tlsConfig = FileHandler.readTLSConfiguration(CONFIGS_PATH + this.username + TLS_CONFIGURATION_EXTENSION);

		System.setProperty("javax.net.ssl.trustStore", CERTIFICATES_PATH + tlsConfig.getTruststoreFilename());
		System.setProperty("javax.net.ssl.trustStorePassword", "clientTrustedStore");

		SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLContext ctx;
		SSLSocket c = null;
		
		KeyManagerFactory kmf;
		KeyStore ks;
		
		TrustManager[] trustedCerts = new TrustManager[] {new InsecureTrustManager()};
		
		try {

			if(tlsConfig.getAuthenticationType().equals("CLIENTE-SERVIDOR") || 
			   tlsConfig.getAuthenticationType().equals("CLIENTE"))
			{
				// se o cliente tambem tem de se autenticar, vai ter de obter a keystore
				try {
					ctx = SSLContext.getInstance(tlsConfig.getVersion());
					
					ks = KeyStore.getInstance("JKS");
					ks.load(new FileInputStream(CERTIFICATES_PATH + tlsConfig.getPrivateKeyStoreFilename() + KEYSTORE_EXTENSION), this.clientKeyStorePassword);
					
					kmf = KeyManagerFactory.getInstance("SunX509");
					kmf.init(ks, this.clientEntryPassword);
					
					ctx.init(kmf.getKeyManagers(), trustedCerts, null);
					f = ctx.getSocketFactory();
					
				} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException
						| KeyManagementException e) {
					e.printStackTrace();
				}
			}else{
				try {
					ctx = SSLContext.getInstance(tlsConfig.getVersion());
					
					ctx.init(null, trustedCerts, null);
					f = ctx.getSocketFactory();
				} catch (KeyManagementException | NoSuchAlgorithmException e) {
					e.printStackTrace();
				}
			}
			
			c = (SSLSocket) f.createSocket(this.serverAddress, this.serverPort);
			
			//c.setEnabledProtocols(new String[] { tlsConfig.getVersion() });
			//c.setEnabledCipherSuites(new String[] { tlsConfig.getCiphersuite() });
		
			if(tlsConfig.getAuthenticationType().equals("CLIENTE")){
				c.setUseClientMode(false);
			}
			
			c.startHandshake();

			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
			
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

			if(authenticationResult.equals("true")){
				this.authenticationResult = true;
				String crypto = r.readLine();
				this.setCipherConfiguration(crypto);
			}

			w.close();
			r.close();
			c.close();
		} catch (IOException e) {
			System.err.println(e.toString());
		}
	}
}