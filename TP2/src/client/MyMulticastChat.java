package client;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import diffiehellman.MyDigitalSignature;
import diffiehellman.UtilsDH;
import helpers.Utils;
import security.CipherConfiguration;

public class MyMulticastChat extends MulticastChat{

	private static BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
    
    private ArrayList<String> publicKeys;
    
    private KeyPair myPair;
    private MyDigitalSignature myDigitalSign;
    
	public MyMulticastChat(String username, InetAddress group, int port, int ttl, MulticastChatEventListener listener,
			CipherConfiguration cipherConfiguration) throws IOException {
		super(username, group, port, ttl, listener, cipherConfiguration);
		
		this.publicKeys = new ArrayList<String>();
		this.myDigitalSign = new MyDigitalSignature();
	}
	
	@Override
	protected void sendJoin() throws IOException {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);

		dataStream.writeLong(CHAT_MAGIC_NUMBER);
		dataStream.writeInt(JOIN);
		dataStream.writeUTF(username);
		//cant send like this, need to sign it, and with it send the public key, so that the other user can check if its correct 
		dataStream.writeUTF(Utils.toHex(generateDiffieHellman().getEncoded()));
		dataStream.close();

		byte[] data = byteStream.toByteArray();
		DatagramPacket packet = new DatagramPacket(data, data.length, group, msocket.getLocalPort());
		msocket.send(packet);
	}
	
	@Override
	protected void processJoin(DataInputStream istream, InetAddress address, int port) throws IOException {
		super.processJoin(istream, address, port);
		String dhNumber = istream.readUTF();
		byte[] pKey = Utils.hexStringToByteArray(dhNumber);
		
		//transform in a public key received, because it was in a string format
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");	
		    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pKey);
			PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);
			
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
		
		//listener.chatMessageReceived(this.username, this.group, this.msocket.getLocalPort(), "HERE IS MY DH PUBLIC NUMBER; NOW THAT I HAVE RECEIVED FROM THE USER THAT JOINED");
	}

	/**
	 * 
	 * @return
	 */
	private PublicKey generateDiffieHellman(){
		DHParameterSpec  dhParams = new DHParameterSpec(p512, g512);
		
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
			keyGen.initialize(dhParams, UtilsDH.createFixedRandom());
			
			KeyAgreement myKeyAgree = KeyAgreement.getInstance("DH", "BC");
	        KeyPair      myPair = keyGen.generateKeyPair();
	        
	        this.myPair = myPair;
	        
	        myKeyAgree.init(myPair.getPrivate());
	        
	        return myPair.getPublic();
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException
				| InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}

}
