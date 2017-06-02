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

		try {
			// signed the public key for Diffie-Hellman
			byte[] signedDHpubKey = myDigitalSign.signContent(this.myDHPair.getPublic().getEncoded());
			
			System.out.println("DH PUBLIC KEY BEFORE SIGNING: " + Utils.toHex(this.myDHPair.getPublic().getEncoded()));
			System.out.println("DH PUBLIC KEY AFTER SIGNING: " + Utils.toHex(signedDHpubKey));
			
			dataStream.writeUTF("" + signedDHpubKey.length);
			
			dataStream.write(signedDHpubKey);
			System.out.println("send" + signedDHpubKey.toString());
			
			// also needs to send the public key of the signature,
			// so the other party can check the signature	
			dataStream.writeUTF("" + myDigitalSign.getMyPublicKey().length);
			dataStream.write(myDigitalSign.getMyPublicKey());
			
			System.out.println("PUBLIC KEY: " + Utils.toHex(myDigitalSign.getMyPublicKey()));
			
		} catch (Exception e) {
			System.out.println(e.toString());
		}

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
		
		//read the signed DH public key
		int signatureSize = Integer.parseInt(istream.readUTF());
		
		byte[] signedDHPubKey = new byte[signatureSize];
		istream.read(signedDHPubKey);
		
		System.out.println("SIGNED DH PUBLIC KEY IN RECEIVE: " + Utils.toHex(signedDHPubKey));
		
		//read the signature public key
		int signaturePubKeySize = Integer.parseInt(istream.readUTF());
		
		byte[] signaturePubKey = new byte[signaturePubKeySize];
		istream.read(signaturePubKey);
		System.out.println("process" + signedDHPubKey.toString());
		System.out.println("PUBLIC KEY IN RECEIVE: " + Utils.toHex(signaturePubKey));
		
		//convert to PublicKey
		PublicKey sigpk = convertPubKeyByteToPublicKey(signaturePubKey);
		
		//finally, get the DH Public Key
		PublicKey publicDHkey = getDHPublicKey(signedDHPubKey, sigpk);
		
		System.out.println(Utils.toHex(publicDHkey.getEncoded()));
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
	private PublicKey getDHPublicKey(byte[] signedContent, PublicKey sigPubKey) {
		try {
			if(verifySignedContent(signedContent, sigPubKey)){
				return convertPubKeyByteToPublicKey(signedContent);
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Auxiliar method to convert the enconded public key byte array into a PublicKey
	 * object.
	 * 
	 * @param pubKeyHex
	 * @return
	 */
	private PublicKey convertPubKeyByteToPublicKey(byte[] pubKeyHex) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyHex);

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

		Signature sig = Signature.getInstance("SHA1withDSA");
		sig.initVerify(sigPubKey);
		sig.update(signedContent);
		return sig.verify(signedContent);
	}
}
