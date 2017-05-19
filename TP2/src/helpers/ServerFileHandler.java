package helpers;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import helpers.RoomPermissions;

public class ServerFileHandler{
	
	private static final String USERFILENAME = "database/usersPasswords.txt";
	private static final String USERPERMFILENAME = "database/acessControl.txt";

	/**
	 * 
	 * @return
	 */
	public static boolean isUserAllowed(String roomAddres, String username) {
		try (BufferedReader br = new BufferedReader(new FileReader(USERPERMFILENAME))) {
			
			HashMap<String, ArrayList<String>> dataStruct = new HashMap<String, ArrayList<String>>();
			
			String line = br.readLine();
			while (line != null) {
				// if has # it's a comment, so ignore it
				if (!line.startsWith("#")) {
					String[] lineSplitted = line.split(":");
					String roomName = lineSplitted[0];
					String users = lineSplitted[1].split("#")[0].trim();
					
					String[] parsedUsers = users.split(" ");
					ArrayList<String> usersList = new ArrayList<String>();
					
					for(int i = 0; i < parsedUsers.length; i++){
						usersList.add(parsedUsers[i]);
					}
					dataStruct.put(roomName, usersList);
				}
				line = br.readLine();
			}

			return new RoomPermissions(dataStruct).isAllowed(roomAddres, username);
		} catch (IOException e) {
			System.out.println("Failed to read the file." + e.getMessage());
		}
		return false;
	}
	
	/**
	 * 
	 * @return
	 */
	public static String getUserPasswordFromFile(String username) {
		String password = FileHandler.getKeyValuesFromFile(USERFILENAME).get(username);
		return password == null ? "" : password;
	}
}
