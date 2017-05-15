package server;

import java.net.InetAddress;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import com.sun.net.httpserver.HttpServer;

import security.InsecureTrustManager;

public class RestServer {

	public static void main(String[] args) throws Exception {
		URI baseUri = UriBuilder.fromUri("https://0.0.0.0/").port(9090).build();
		ResourceConfig config = new ResourceConfig();
		config.register(new ServerResource());

		// configure the SSLContext with a TrustManager
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(new KeyManager[0], new TrustManager[] {new InsecureTrustManager()}, new SecureRandom());
        SSLContext.setDefault(ctx);
        
		HttpServer server = JdkHttpServerFactory.createHttpServer(baseUri, config, ctx);
		System.err.println("SSL REST Server ready... @ " + InetAddress.getLocalHost().getHostAddress());
		
		
	}
	
	
}


