
public class MyMChatCliente extends MChatCliente {
	
	//tipo de encriptação
	//algoritmo de hashing
	//tudo isso é lido do ficheiro de configuração
	public MyMChatCliente(){
		super();
	}

	public void SendMesage(){
		//encriptar a mensagem por aqui?
		//antes de a enviar, utilizar o algoritmo de encriptação que está no ficheiro de configuração.
		super.sendMessage();
	}

	public static void main(String[] args) {
		MChatCliente.main(args);
	}
}
