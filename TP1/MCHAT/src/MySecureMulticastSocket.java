import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;

public class MySecureMulticastSocket extends MulticastSocket {

	//https://docs.oracle.com/javase/7/docs/api/java/net/MulticastSocket.html
	public MySecureMulticastSocket() throws IOException{
		super();
	}
	
	@Override
	public void send(DatagramPacket dgPacket){
		
	}
	
}