package diffiehellman;

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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import client.MulticastChat;
import client.MulticastChatEventListener;
import client.MySecureMulticastSocket;
import helpers.Utils;
import security.CipherConfiguration;

public class MyMulticastChat extends MulticastChat {

	private static BigInteger g512 = new BigInteger(
			"153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc",
			16);
	private static BigInteger p512 = new BigInteger(
			"9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b",
			16);

	private ArrayList<PublicKey> publicKeys;

	private KeyPair myDHPair;
	private MyDigitalSignature myDigitalSign;

	public MyMulticastChat(String username, InetAddress group, int port, int ttl, MulticastChatEventListener listener,
			CipherConfiguration cipherConfiguration) throws IOException {
		super(username, group, ttl, listener);
		
		// create & configure multicast socket
		msocket = new MySecureMulticastSocket(port, cipherConfiguration);
		msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
		msocket.setTimeToLive(ttl);
		msocket.joinGroup(group);

		this.publicKeys = new ArrayList<PublicKey>();
		this.myDigitalSign = new MyDigitalSignature();

		generateDiffieHellman();
		
		// start receive thread and send multicast join message
		start();
		sendJoin();
	}

	/**
	 * Handler to send information when a user joins the chat
	 */
	@Override
	protected void sendJoin() throws IOException {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);

		dataStream.writeLong(CHAT_MAGIC_NUMBER);
		dataStream.writeInt(JOIN);
		dataStream.writeUTF(username);

		// signed the public key for Diffie-Hellman
		try {
			String signedDHpubKey = myDigitalSign.signContent(this.myDHPair.getPublic().getEncoded());
			
			System.out.println("DH PUBLIC KEY BEFORE SIGNING: " + Utils.toHex(this.myDHPair.getPublic().getEncoded()));
			System.out.println("DH PUBLIC KEY AFTER SIGNING: " + signedDHpubKey);
			dataStream.writeUTF(signedDHpubKey);
		} catch (Exception e) {
			System.out.println(e.toString());
		}

		// also needs to send the public key of the signature,
		// so the other party can check the signature
		dataStream.writeUTF(myDigitalSign.getMyPublicKeyHex());
		
		System.out.println("SIGNATURE PUBLIC KEY: " + myDigitalSign.getMyPublicKeyHex());

		dataStream.close();

		byte[] data = byteStream.toByteArray();
		DatagramPacket packet = new DatagramPacket(data, data.length, group, msocket.getLocalPort());
		msocket.send(packet);
	}

	/**
	 * Handler to process the join message received, with the DH parameters
	 */
	@Override
	protected void processJoin(DataInputStream istream, InetAddress address, int port) throws IOException {
		super.processJoin(istream, address, port);
		String hexSignedContent = istream.readUTF();
		String sigPubKey = istream.readUTF();

		System.out.println("RECEIVED SIGNATURE PUBLIC KEY: " + sigPubKey);
		System.out.println("RECEIVED DH PUBLIC KEY SIGNED: " + hexSignedContent);
		
		String a = getDHPublicKey(hexSignedContent, sigPubKey);
		
		System.out.println("RECEIVED DH PUBLIC KEY UNSIGNED: " + a);
		

		// byte[] pKey = Utils.hexStringToByteArray(dhNumber);

		// transform in a public key received, because it was in a string format
		// adds the public key received to its list
		// publicKeys.add(publicKey);
	}

	/**
	 * Generate a Diffie-Hellman KeyPair for the user
	 * 
	 * @return
	 */
	private void generateDiffieHellman() {
		DHParameterSpec dhParams = new DHParameterSpec(p512, g512);

		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
			keyGen.initialize(dhParams, UtilsDH.createFixedRandom());

			KeyAgreement myKeyAgree = KeyAgreement.getInstance("DH", "BC");
			KeyPair myPair = keyGen.generateKeyPair();

			this.myDHPair = myPair;
			myKeyAgree.init(myPair.getPrivate());

		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException
				| InvalidKeyException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 
	 * @param hexSignedContent
	 * @param sigPubKeyHex
	 * @return
	 */
	private String getDHPublicKey(String hexSignedContent, String sigPubKeyHex) {
		byte[] signedContent = Utils.hexStringToByteArray(hexSignedContent);
		PublicKey sigPubKey = convertPubKeyHexToPublicKey(sigPubKeyHex);
		
		try {
			verifySignedContent(signedContent, sigPubKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
		}
		
		String unsignedDHKey = Utils.toHex(signedContent);

		return unsignedDHKey;
	}

	/**
	 * Auxiliar method to convert the enconded public key hex into a PublicKey
	 * object.
	 * 
	 * @param pubKeyHex
	 * @return
	 */
	private PublicKey convertPubKeyHexToPublicKey(String pubKeyHex) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyHex.getBytes());

			return keyFactory.generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 
	 * @param signedContent
	 * @param sigPubKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	private boolean verifySignedContent(byte[] signedContent, PublicKey sigPubKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		
		MyDigitalSignature tempSignature = new MyDigitalSignature();

		Signature sig = Signature.getInstance("SHA1withDSA");
		sig.initVerify(sigPubKey);
		sig.update(signedContent);
		return sig.verify(signedContent);
	}
}
