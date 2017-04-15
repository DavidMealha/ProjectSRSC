package server;

import java.net.InetAddress;
import java.net.URI;
import javax.net.ssl.SSLContext;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import com.sun.net.httpserver.HttpServer;

public class RestServer {

	public static void main(String[] args) throws Exception {
		URI baseUri = UriBuilder.fromUri("https://0.0.0.0/").port(9090).build();
		ResourceConfig config = new ResourceConfig();
		config.register( new ServerResource());

		HttpServer server = JdkHttpServerFactory.createHttpServer(baseUri, config, SSLContext.getDefault());
		System.err.println("SSL REST Server ready... @ " + InetAddress.getLocalHost().getHostAddress());
	}
}
