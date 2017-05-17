package client;

import java.util.*;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;

import helpers.TLSConfiguration;

public class TLSClient {
	
	public static void main(String[] args) {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		PrintStream out = System.out;

		File file = new File(".");
		for(String fileNames : file.list()) System.out.println(fileNames);
		
		System.setProperty("javax.net.ssl.trustStore", "src/client/alicetruststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "alicetrust");
		
		SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
		try {
			
			SSLSocket c = (SSLSocket) f.createSocket(args[0], Integer.parseInt(args[1]));

			// enable TLSv1.2 and ciphersuites
//			c.setEnabledProtocols(new String[] { "TLSv1.2" });
//			c.setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_256_CBC_SHA256" });

			printSocketInfo(c);
			
			//ter que ter o startHandshake depois da parameterização
			c.startHandshake();
			
			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
			
			String m = null;
			
			while ((m = r.readLine()) != null) {
				out.println(m);
				m = in.readLine();
				
				//send this to the server..
				w.write(m, 0, m.length());
				w.newLine();
				w.flush();
			}
			
			w.close();
			r.close();
			c.close();
		} catch (IOException e) {
			e.printStackTrace();
			//System.err.println(e.toString());
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