package diffiehellman;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

import client.MulticastChat;
import client.MulticastChatEventListener;
import client.MySecureMulticastSocket;
import helpers.Utils;
import security.CipherConfiguration;
import security.DigestHandler;

public class MyMulticastChat extends MulticastChat {

	private static BigInteger g512 = new BigInteger(
			"153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc",
			16);

	private static BigInteger p512 = new BigInteger(
			"9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b",
			16);

	private HashMap<String, PublicKey> publicKeys;

	private KeyPair myDHPair;
	private MyDigitalSignature myDigitalSign;
	private KeyAgreement myKeyAgreement;

	private byte[] myDHSecret;

	public static final int DH_MESSAGE = 4;

	public MyMulticastChat(String username, InetAddress group, int port, int ttl, MulticastChatEventListener listener,
			CipherConfiguration cipherConfiguration) throws IOException {
		super(username, group, ttl, listener);

		// create & configure multicast socket
		msocket = new MySecureMulticastSocket(port, cipherConfiguration);
		msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
		msocket.setTimeToLive(ttl);
		msocket.joinGroup(group);

		this.publicKeys = new HashMap<String, PublicKey>();
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
			byte[] signedDHpubKey = myDigitalSign.signContent(this.myDHPair.getPublic().getEncoded());

			dataStream.writeUTF(Utils.toHex(this.myDHPair.getPublic().getEncoded()));
			dataStream.writeUTF(Utils.toHex(signedDHpubKey));
			dataStream.writeUTF(Utils.toHex(myDigitalSign.getMyPublicKey()));
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

		String hexDhPubKey = istream.readUTF();
		byte[] dhPubKey = Utils.hexStringToByteArray(hexDhPubKey);

		String hexSignedDHPubKey = istream.readUTF();
		byte[] signedDHPubKey = Utils.hexStringToByteArray(hexSignedDHPubKey);

		String hexSignPubKey = istream.readUTF();
		byte[] signaturePubKey = Utils.hexStringToByteArray(hexSignPubKey);

		PublicKey signPublicKey = convertPubKeyByteToPublicKey(signaturePubKey, this.myDigitalSign.getKeyAlgorithm());
		PublicKey publicDHkey = getDHPublicKey(dhPubKey, signedDHPubKey, signPublicKey);

		publicKeys.put(hexDhPubKey, publicDHkey);

		try {
			Iterator it = publicKeys.entrySet().iterator();
			Key auxKey;
			while(it.hasNext()){
				auxKey = myKeyAgreement.doPhase(publicDHkey, false);
				
				if(!it.hasNext()){
					myKeyAgreement.doPhase(auxKey, true);
				}
			}
			
			myDHSecret = myKeyAgreement.generateSecret();
			msocket.setCipherKey(Utils.toHex(myDHSecret));

			//sendDHMessage();

		} catch (InvalidKeyException | IllegalStateException e) {
			System.out.println(e.toString());
		}
	}

	/**
	 * 
	 * @throws IOException
	 */
	protected void sendDHMessage(byte[] keyAgreement) throws IOException {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);

		dataStream.writeLong(CHAT_MAGIC_NUMBER);
		dataStream.writeInt(DH_MESSAGE);
		dataStream.writeUTF(Utils.toHex(keyAgreement));

		byte[] data = byteStream.toByteArray();
		DatagramPacket packet = new DatagramPacket(data, data.length, group, msocket.getLocalPort());
		msocket.send(packet);
	}

	/**
	 * 
	 * @param istream
	 * @param address
	 * @param port
	 * @throws IOException
	 */
	protected void processDHMessage(DataInputStream istream, InetAddress address, int port) throws IOException {
		// read the public keys, process them, and generate the secret
		String keyAgreementHex = istream.readUTF();

		//PublicKey key = (PublicKey) new SecretKeySpec(Utils.hexStringToByteArray(keyAgreementHex), "DH");

		try {
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
			
			PublicKey pubKey = keyFactory.generatePublic(
					new DHPublicKeySpec(new BigInteger(1, Utils.hexStringToByteArray(keyAgreementHex)), this.p512, this.g512));

			myKeyAgreement.doPhase(pubKey, true);
			//myDHSecret = DigestHandler.hashWithSHA("SHA-256", myKeyAgreement.generateSecret());
			myDHSecret = myKeyAgreement.generateSecret("AES").getEncoded();
			msocket.setCipherKey(Utils.toHex(myDHSecret));
			
			System.out.println("PROCESS DH MESSAGE KEY: " + Utils.toHex(myDHSecret));
			
		} catch (InvalidKeyException | IllegalStateException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		byte[] buffer = new byte[65508];
		DatagramPacket packet = null;
		while (isActive) {
			try {

				// Comprimento do DatagramPacket RESET antes do request
				packet = new DatagramPacket(buffer, buffer.length);
				// packet.setLength(buffer.length);
				msocket.receive(packet);

				DataInputStream istream = new DataInputStream(
						new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength()));

				long magic = istream.readLong();

				if (magic != CHAT_MAGIC_NUMBER) {
					continue;

				}
				int opCode = istream.readInt();
				switch (opCode) {
				case JOIN:
					processJoin(istream, packet.getAddress(), packet.getPort());
					break;
				case LEAVE:
					processLeave(istream, packet.getAddress(), packet.getPort());
					break;
				case MESSAGE:
					processMessage(istream, packet.getAddress(), packet.getPort());
					break;
				case DH_MESSAGE:
					processDHMessage(istream, packet.getAddress(), packet.getPort());
					break;
				default:
					error("Cod de operacao desconhecido " + opCode + " enviado de " + packet.getAddress() + ":"
							+ packet.getPort());
				}

			} catch (InterruptedIOException e) {

				/**
				 * O timeout e usado apenas para forcar um loopback e testar o
				 * valor isActive
				 */

			} catch (Throwable e) {
				// error("Processing error: " + e.getClass().getName() + ": " +
				// e.getMessage());
				e.printStackTrace();
			}
		}

		try {
			msocket.close();
		} catch (Throwable e) {
		}
	}

	/**
	 * Generate a Diffie-Hellman KeyPair for the user
	 * 
	 * @return
	 */
	private void generateDiffieHellman() {
		DHParameterSpec dhParams = new DHParameterSpec(p512, g512);

		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
			keyGen.initialize(dhParams, new SecureRandom());

			this.myKeyAgreement = KeyAgreement.getInstance("DH");
			KeyPair myPair = keyGen.generateKeyPair();

			this.myDHPair = myPair;
			this.myKeyAgreement.init(myPair.getPrivate());

		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * @param hexSignedContent
	 * @param sigPubKeyHex
	 * @return
	 */
	private PublicKey getDHPublicKey(byte[] dhPubKey, byte[] signedContent, PublicKey sigPubKey) {
		try {
			if (verifySignedContent(dhPubKey, signedContent, sigPubKey)) {
				return convertPubKeyByteToPublicKey(dhPubKey, "DH");
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Auxiliar method to convert the enconded public key byte array into a
	 * PublicKey object.
	 * 
	 * @param pubKeyHex
	 * @return
	 */
	private PublicKey convertPubKeyByteToPublicKey(byte[] pubKeyHex, String algorithm) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyHex);

			return keyFactory.generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
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
	private boolean verifySignedContent(byte[] dhPubKey, byte[] signedContent, PublicKey sigPubKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature sig = Signature.getInstance(this.myDigitalSign.getSignatureAlgorithm());
		sig.initVerify(sigPubKey);
		sig.update(dhPubKey);
		return sig.verify(signedContent);
	}
}
