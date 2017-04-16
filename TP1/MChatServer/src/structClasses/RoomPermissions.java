package structClasses;

import java.util.ArrayList;
import java.util.HashMap;

public class RoomPermissions {
	
	private HashMap<String, ArrayList<String>> permData;
	
	public RoomPermissions(){
		permData = new HashMap<String, ArrayList<String>>();
	}
	
	public RoomPermissions(HashMap<String, ArrayList<String>> dataStruct){
		permData = dataStruct;
	}
	
	public void addRoom(String roomName, ArrayList<String> listUsers){
		permData.put(roomName, listUsers);
	}
	
	public ArrayList<String> getRoomPerm(String roomName){
		return permData.get(roomName);
	}
	
	public boolean isAllowed(String roomName, String user){
		
		ArrayList<String> authUsers = permData.get(roomName);
		if(authUsers == null)
			return false;
		
		if(authUsers.contains(user))
			return true;
		else
			return false;
	}
}
