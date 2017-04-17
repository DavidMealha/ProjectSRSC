package server;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import auxiliaryClasses.Utils;
import fileManagement.FileHandler;
import fileManagement.ServerFileHandler;
import security.MessageCipherHandler;
import security.PBEConfiguration;
import structClasses.RoomPermissions;

@Path("/Authentication")
public class ServerResource {

	private HashMap<String, String> users = ServerFileHandler.getUserFromFile();
	private RoomPermissions rp = ServerFileHandler.getRoomPermissions();

	private static final String LOGFILESDIR = "configs/";
	private static final String PBEEXTENSION = ".pbe";
	private static final String CRYPTOEXTENSION = ".crypto";
	
	@POST
	@Path("/{userName}/{roomName}")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public Response get(@PathParam("userName") String userName, @PathParam("roomName") String roomName, byte[] message)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException,
			ClassNotFoundException {

		System.out.println("Received request!");
		String userHashedPassword = users.get(userName);
		
		// pbe file need to have room + userName
		String pbeFileName = roomName + "_" + userName;
		PBEConfiguration pbe = FileHandler.readPBEncryptionFile(LOGFILESDIR + pbeFileName + PBEEXTENSION);

		// decipher to obtain the remaining parameters
		byte[] decipheredPayload = MessageCipherHandler.uncipherMessageWithPBE(userHashedPassword, message, pbe);
		
		ByteArrayInputStream inputStream = new ByteArrayInputStream( decipheredPayload );
		
		//get the iv bytes
		byte[] ivNumberBytes = new byte[4];
		inputStream.read(ivNumberBytes,0,4);
		byte[] ivParamenters = new byte[12];
		inputStream.read(ivParamenters, 0, 12);
		
		ByteBuffer numBuffer = ByteBuffer.wrap(ivNumberBytes);
		int nonce = numBuffer.getInt();
		
		byte[] bytesPassword = new byte[inputStream.available()];
		inputStream.read(bytesPassword,0,inputStream.available());
		
		String insideCipherAshPass = Utils.toString(bytesPassword);

		if (!userHashedPassword.equals(insideCipherAshPass))
			return Response.status(Status.FORBIDDEN).build();
		
		nonce += 1;
		
		
		// Know the password is verified we need to fetch a raw criptoFile and
		// cipher with user password, its only geting a raw crypto file
		IvParameterSpec generatedNonce = Utils.createCtrIvForAES(nonce, new SecureRandom());
		InputStream cryptoInputStream = new FileInputStream(new File(LOGFILESDIR + roomName + ".txt"));
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write( generatedNonce.getIV() );
		outputStream.write(outputStream.toByteArray());
		
		byte[] uncipheredMessage = outputStream.toByteArray();

		byte[] cipheredMessageFile = MessageCipherHandler.cipherMessageWithPBE(userHashedPassword, pbe, uncipheredMessage);

		return Response.ok(cipheredMessageFile).build();
	}
}