package application;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class MySecureMulticastSocket extends MulticastSocket {

	private CipherConfiguration cipherConfiguration;
	private PBEConfiguration pbe;

	// https://docs.oracle.com/javase/7/docs/api/java/net/MulticastSocket.html
	public MySecureMulticastSocket() throws IOException {
		super();
	}

	public MySecureMulticastSocket(int port) throws IOException {
		super(port);
	}

	@Override
	public void joinGroup(InetAddress group) throws IOException {
		// get ip of multicast group
		String pbeFilename = "configs/" + group.getHostAddress() + ".pbe";

		// class with all the pbe configuration for the address
		this.setPbe(FileHandler.readPBEncryptionFile(pbeFilename));

		try {
			this.setCipherConfiguration(CipherHandler.uncipherFileWithPBE("password", group.getHostAddress()));
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| ClassNotFoundException e) {
			System.out.println("Failed to parse the ciphersuite." + e.getMessage());
			// e.printStackTrace();
		}

		super.joinGroup(group);
	}

	@Override
	public void send(DatagramPacket dgPacket) throws IOException {
		// manipular o buffer que esta no data gram
		byte[] buffer = dgPacket.getData();

		try {
			buffer = CipherHandler.cipherText(buffer, this.cipherConfiguration);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
			| InvalidAlgorithmParameterException | ShortBufferException | IllegalBlockSizeException
			| BadPaddingException | IllegalStateException e1) {
			System.out.println("Failed to cipher message." + e1.getMessage());
		}
		// after encrypting the buffer, it's time to finally set it
		dgPacket.setData(buffer);

		// at the end, call the super, to send the datagram to the multicast host
		try {
			super.send(dgPacket);
		} catch (IOException e) {
			System.out.println(
					"Falhou o envio do datagram." + "Na classe:" + e.getClass().getName() + " | " + e.getMessage());
			e.printStackTrace();
		}
	}

	@Override
	public void receive(DatagramPacket dgPacket) throws IOException {
		
		//first receive the datagram to get the real buffer with the correct length
		super.receive(dgPacket);
		
		// create a byte[] with the ciphered data
		byte[] buffer = new byte[dgPacket.getLength()]; 
		System.arraycopy(dgPacket.getData(), dgPacket.getOffset(), buffer, 0, dgPacket.getLength());
				
		try {
			buffer = CipherHandler.uncipherText(buffer, this.cipherConfiguration);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
			| InvalidAlgorithmParameterException | ShortBufferException | IllegalBlockSizeException
			| BadPaddingException | IllegalStateException e) {
			System.out.println("Failed to uncipher message." + e.getMessage());
		}
		//set the data of the packet with the unciphered buffer, changing by reference
		dgPacket.setData(buffer);	
	}

	public CipherConfiguration getCipherConfiguration() {
		return cipherConfiguration;
	}

	public void setCipherConfiguration(CipherConfiguration cipherConfiguration) {
		this.cipherConfiguration = cipherConfiguration;
	}

	public PBEConfiguration getPbe() {
		return pbe;
	}

	public void setPbe(PBEConfiguration pbe) {
		this.pbe = pbe;
	}

}