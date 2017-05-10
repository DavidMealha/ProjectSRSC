package fileManagement;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import structClasses.RoomPermissions;

public class ServerFileHandler {
	
	private static final String USERFILENAME = "dbLogs/users.txt";
	private static final String USERPERMFILENAME = "dbLogs/permissions.txt";

	
	public static RoomPermissions getRoomPermissions() {
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

			return new RoomPermissions(dataStruct);
		} catch (IOException e) {
			System.out.println("Failed to read the file." + e.getMessage());
		}
		return null;
	}
	
	// 
	public static HashMap<String, String> getUserFromFile() {
		
		try (BufferedReader br = new BufferedReader(new FileReader(USERFILENAME))) {

			HashMap<String, String> userHash = new HashMap<String, String>();
			
			String line = br.readLine();
			while (line != null) {
				// if has # it's a comment, so ignore it
				if (!line.startsWith("#")) {
					String[] lineSplitted = line.split(":");
					String name = lineSplitted[0];
					String ashKey = lineSplitted[1].split("#")[0].trim();

					userHash.put(name, ashKey);
				}
				line = br.readLine();
			}

			return userHash;
		} catch (IOException e) {
			System.out.println("Failed to read the file." + e.getMessage());
		}
		return null;
	}
}
