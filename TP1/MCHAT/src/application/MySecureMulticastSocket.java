package application;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MySecureMulticastSocket extends MulticastSocket {

	private CipherConfiguration cipherConfiguration;
	private PBEConfiguration pbe;
	
	// https://docs.oracle.com/javase/7/docs/api/java/net/MulticastSocket.html
	public MySecureMulticastSocket() throws IOException {
		super();
//		this.cipherConfiguration = new CipherConfiguration(); 
//		this.pbe = new PBEConfiguration();
	}

	public MySecureMulticastSocket(int port) throws IOException {
		super(port);
//		this.cipherConfiguration = new CipherConfiguration(); 
//		this.pbe = new PBEConfiguration();
	}

	@Override
	public void joinGroup(InetAddress group) throws IOException {
		// get ip of multicast group
		String pbeFilename = "configs/" + group.getHostAddress() + ".pbe";

		// class with all the pbe configuration for the address
		this.setPbe(FileHandler.readPBEncryptionFile(pbeFilename));
		
		try {
			this.setCipherConfiguration(CipherHandler.uncipherFileWithPBE("password", group.getHostAddress()));
		} 
		catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {	
			System.out.println("Failed to uncipher the ciphersuite." + e.getMessage());
			//e.printStackTrace();
		}

		super.joinGroup(group);
	}

	@Override
	public void send(DatagramPacket dgPacket) {
		// manipular o buffer que esta no data gram
		byte[] buffer = dgPacket.getData();
		
		try {
			buffer = CipherHandler.cipherText(buffer, cipherConfiguration);
		} 
		catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e1) {
			System.out.println("Failed to cipher message." + e1.getMessage());
		}
		
		//after encrypting the buffer, it's time to finally send it
		dgPacket.setData(buffer);

		// at the end, call the super, to send the datagram to the multicast host
		try {
			super.send(dgPacket);
		} catch (IOException e) {
			System.out.println(
					"Falhou o envio do datagram." + "Na classe:" + e.getClass().getName() + " | " + e.getMessage());
		}
	}

	public CipherConfiguration getCipherConfiguration() {
		return cipherConfiguration;
	}

	public void setCipherConfiguration(CipherConfiguration cipherConfiguration) {
//		this.cipherConfiguration.setCiphersuite(cipherConfiguration.getCiphersuite());
//		this.cipherConfiguration.setKeySize(keySize);
//		this.cipherConfiguration.setKeyValue(keyValue);
//		this.cipherConfiguration.setMacAlgorithm(macAlgorithm);
//		this.cipherConfiguration.setMacKeyValue(macKeyValue);
//		this.cipherConfiguration.setMacKeyValue(macKeyValue);
		this.cipherConfiguration = cipherConfiguration;
	}

	public PBEConfiguration getPbe() {
		return pbe;
	}

	public void setPbe(PBEConfiguration pbe) {
		this.pbe = pbe;
	}

	//
	// public void receive(DatagramPacket dgPacket){
	//
	// }

	// encriptar a mensagem por aqui?
	// antes de a enviar, utilizar o algoritmo de encriptação que está no
	// ficheiro de configuração.
	//
	// Garantir aos utilizadores confidencialidade, integridade e autenticidade
	// das mensagens
	// Garantir também a autenticação e o controlo de acesso às conversas,
	// apenas para
	// utilizadores devidamente autorizados.
	//
	// Os ficheiros de configuração estão protegidos através de PBE,
	// a configuração esta em sala.crype(e.g 224.10.101.0),
	// send o conteúdo acessível no inicio da aplicação ao pedir a password
	// ao utilizador
	//
	// A parameterização do esquema PBE deve de estar noutro ficheiro,
	// mais concretamente sala.pbe(e.g 224.10.10.10.pbe)
	//
	// O sistema deverá ser totalmente parameterizavel, de modo a permitir
	// encriptação
	// com os algoritmos presentes nos ficheiros de configuração.
	//
	// Ciphersuite <algorithm/mode/padding> exemple: AES/CBC/PKCS #5
	//
	// A mensagem deverá ser cifrada com a seguinte estrutura:
	// VER || 0x00 || TAMANHO DO PAYLOAD || PAYLOAD
	// PAYLOAD - mensagem cifrada com prova de autenticidade e integridade e um
	// nonce(??)

	
}