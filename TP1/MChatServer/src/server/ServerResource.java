package server;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import fileManagement.FileHandler;
import fileManagement.ServerFileHandler;
import security.MessageCipherHandler;
import security.PBEConfiguration;
import structClasses.RoomPermissions;

@Path("/MChatServer")
public class ServerResource {

	private HashMap<String, String> users = ServerFileHandler.getUserFromFile();
	private RoomPermissions rp = ServerFileHandler.getRoomPermissions();
	
	@POST
	@Path("/{userName}/{roomName}")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public Response get(@PathParam("userName")String userName, @PathParam("roomName")String roomName, byte[] message) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		
		String userAshPass = users.get(userName);
		String pbeFileName = roomName +"_"+ userName; // pbe file need to have room + userName
		PBEConfiguration pbe = FileHandler.readPBEncryptionFile("configs/" + pbeFileName + ".pbe");
		
		// decipher to obtain the remaining parameters
		String[] decipheredPayload = MessageCipherHandler.uncipherMessageWithPBE(userAshPass, message, pbe);
		
		// Nounce is still not used. It is required to update the nonce inside .pbe file??
		int nonce = Integer.parseInt(decipheredPayload[0]);
		String insideCipherAshPass = decipheredPayload[1];
		
		if(!userAshPass.equals(insideCipherAshPass))
			return Response.status(Status.FORBIDDEN).build();
		
		//Know the password is verified we need to fetch a raw criptoFile and cipher with user password, its only geting a raw crypto file
		InputStream cryptoInputStream = new FileInputStream(new File("configs/" +roomName +".txt"));
		byte[] messageFile = new byte[cryptoInputStream.available()];
		cryptoInputStream.read(messageFile, 0 , cryptoInputStream.available());
		
		byte[] cipheredMessageFile = MessageCipherHandler.cipherMessageWithPBE(userAshPass, pbe, messageFile);	
		
		return Response.ok(cipheredMessageFile).build();
	}
}