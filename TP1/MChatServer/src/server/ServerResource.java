package server;

import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/server")
public class ServerResource {

	String value = "default";
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public String get() {
		return value;
	}

	@PUT
	@Produces(MediaType.APPLICATION_JSON)
	public void set( String val) {
		value = val;
	}

}