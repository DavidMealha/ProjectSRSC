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
}
