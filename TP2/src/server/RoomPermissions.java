package server;

import java.util.ArrayList;
import java.util.HashMap;

public class RoomPermissions {
	
	private HashMap<String, ArrayList<String>> accessControlData;
	
	public RoomPermissions(){
		accessControlData = new HashMap<String, ArrayList<String>>();
	}
	
	public RoomPermissions(HashMap<String, ArrayList<String>> dataStruct){
		accessControlData = dataStruct;
	}
	
	public void addRoom(String roomName, ArrayList<String> listUsers){
		accessControlData.put(roomName, listUsers);
	}
	
	public ArrayList<String> getRoomPerm(String roomName){
		return accessControlData.get(roomName);
	}
	
	public boolean isAllowed(String roomName, String user){
		
		ArrayList<String> authUsers = accessControlData.get(roomName);
		if(authUsers == null)
			return false;
		
		if(authUsers.contains(user))
			return true;
		else
			return false;
	}
}
