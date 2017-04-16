package fileManagement;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import security.AshDigest;

public class UserGenerator {

	private static final String USERFILENAME = "dbLogs/users.txt";
	
	private static final String[] users = {"Alice" , "Bob", "Ze"};
	private static final String[] usersPassword = {"passwordAlice" , "passwordBob", "passwordZe"};


	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
		
		if(users.length != usersPassword.length){
			System.out.println("Wrong sizes");
			System.exit(1);		
		}
		
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(USERFILENAME))) {
			
			for(int i = 0; i < users.length; i++){
				bw.write(users[i] + ":" + AshDigest.ashPassword(usersPassword[i]) + "\n");
			}

			bw.close();
			System.out.println("users file created");
			
		} catch (IOException e) {
			System.out.println("Failed to write users file." + e.getMessage());
		}
	}

}
