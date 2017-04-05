
public class MyMChatCliente extends MChatCliente {
	
	//tipo de encriptação
	//algoritmo de hashing
	//tudo isso é lido do ficheiro de configuração
	public MyMChatCliente(){
		super();
	}

	@Override
	protected void doSendMesage(String message){
		//encriptar a mensagem por aqui?
		//antes de a enviar, utilizar o algoritmo de encriptação que está no ficheiro de configuração.
		//
		//Garantir aos utilizadores confidencialidade, integridade e autenticidade das mensagens
		//Garantir também a autenticação e o controlo de acesso às conversas, apenas para
		//utilizadores devidamente autorizados.
		//
		//Os ficheiros de configuração estão protegidos através de PBE, 
		//a configuração esta em sala.crype(e.g 224.10.101.0),
		//send o conteúdo acessível no inicio da aplicação ao pedir a password ao utilizador
		//
		//A parameterização do esquema PBE deve de estar noutro ficheiro,
		//mais concretamente sala.pbe(e.g 224.10.10.10.pbe)
		//
		//O sistema deverá ser totalmente parameterizavel, de modo a permitir encriptação
		//com os algoritmos presentes nos ficheiros de configuração.
		//
		//Ciphersuite <algorithm/mode/padding> exemple: AES/CBC/PKCS #5
		//
		//A mensagem deverá ser cifrada com a seguinte estrutura:
		//VER || 0x00 (??) || TAMANHO DO PAYLOAD || PAYLOAD
		//PAYLOAD - mensagem cifrada com prova de autenticidade e integridade e um nonce(??)
		






	}

	public static void main(String[] args) {
		MChatCliente.main(args);
	}
}
