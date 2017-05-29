package client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;

import security.CipherConfiguration;

public class MyMulticastChat extends MulticastChat{

	private static BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
    
	public MyMulticastChat(String username, InetAddress group, int port, int ttl, MulticastChatEventListener listener,
			CipherConfiguration cipherConfiguration) throws IOException {
		super(username, group, port, ttl, listener, cipherConfiguration);
	}

}
