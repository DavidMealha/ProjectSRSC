package client;

import java.util.*;
import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

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
	private String clientKeyStorePassword;

	public TLSClient(String username, String hashedPassword, String multicastAddress, String clientKeyStorePassword) {
		this.username = username;
		this.hashedPassword = hashedPassword;
		this.multicastAddress = multicastAddress;
		this.clientKeyStorePassword = clientKeyStorePassword;
	}

	/**
	 * 
	 */
	public void run(){
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		PrintStream out = System.out;
		
		// read the tls configuration file
		TLSConfiguration tlsConfig = FileHandler.readTLSConfiguration(CONFIGS_PATH + this.username + TLS_CONFIGURATION_EXTENSION);
		
		System.setProperty("javax.net.ssl.trustStore", "certificates/" + tlsConfig.getTruststoreFilename());
		System.setProperty("javax.net.ssl.trustStorePassword", "clientTrustedStore");
		
		SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
		try {
			
			SSLSocket c = (SSLSocket) f.createSocket("localhost", 4443);
			
			//ter que ter o startHandshake depois da parameterização
			c.startHandshake();
			
			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
			
			String hashedPwd = null;
			try {
				hashedPwd = DigestHandler.hashPassword("clientPassword");
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				e.printStackTrace();
			}
			System.out.println(hashedPwd);
			
			w.write(hashedPwd);
			w.newLine();
			w.flush();
			
			w.close();
			r.close();
			c.close();
		} catch (IOException e) {
			e.printStackTrace();
			//System.err.println(e.toString());
		}
	}
	
	public static void main(String[] args) {
		
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