package server;

import java.util.HashMap;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import fileManagement.ServerFileHandler;
import structClasses.RoomPermissions;

@Path("/MChatServer")
public class ServerResource {

	private HashMap<String, String> users = ServerFileHandler.getUserFromFile();
	private RoomPermissions rp = ServerFileHandler.getRoomPermissions();
	
	@GET
	@Path("/getPermitions")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public String get(String userName, byte[] message) {
		
		String userAshPass = users.get(key)
		byte[] de
		
		
		return value;
	}
}