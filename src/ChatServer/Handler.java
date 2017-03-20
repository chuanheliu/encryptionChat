package ChatServer;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import Protocol.KeyTool;
import Protocol.Protocol;
import Protocol.SimpleProtocol;

public class Handler implements Runnable{

	private Socket socket = null;
	private Protocol protocol = new SimpleProtocol();
	private BufferedReader in;
	private DataOutputStream out;
	private Server server;
	private String username;
	private Key key2;
	private Key key1;


	public Handler(Socket socket) {
		this.socket = socket;
	}

	public void sendToClient(String... args){
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key2);
			byte[] bytes = (protocol.createMessage(args)).getBytes();
			byte[] result = cipher.doFinal(bytes); 
			String base64 = Base64.getEncoder().encodeToString(result);
			out.writeBytes(base64 + "\n");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public String[] getFromClient() throws Exception{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, key2);
		String base64 = in.readLine();
		byte[] result = Base64.getDecoder().decode(base64);
		String codeMessage =new String( cipher.doFinal(result));
		String[] message = protocol.decodeMessage(codeMessage);
		
		return message;
	}

	@Override
	public void run() {
		try {
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new DataOutputStream(socket.getOutputStream());
			server = Server.getInstance();
			
			
			String key1Str = in.readLine();
			// To do: Key exchange
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, KeyTool.getRSAPrivateKey());

			byte[] key1Byte = Base64.getDecoder().decode(key1Str);
			key1 = new SecretKeySpec(cipher.doFinal(key1Byte), "AES");

			cipher = Cipher.getInstance("AES");
			// Create RSA cipher
			cipher.init(Cipher.ENCRYPT_MODE, key1);
			// Create AES key1
			key2 = KeyTool.getAESKey();
			// Encrypt key1 with RSA
			byte[] key2RSA = cipher.doFinal(key2.getEncoded());
			// Transform byte[] to base64 string so that we can send it as a line
			String key2RSA_base64 = Base64.getEncoder().encodeToString(key2RSA);
			//	Key publicKey = RSA_cipher.doFinal(key1.getEncoded());
			out.writeBytes(key2RSA_base64 + "\n");

			// Sign in or create account
			String[] message = getFromClient();
			switch(message[0]){
			case "sign-in":{
				if(server.users.containsKey(message[1])){
					if(server.users.get(message[1]).equals(message[2])){
						this.username = message[1];
						sendToClient("sign-in", "true", "welcome");
					}else{
						sendToClient("sign-in", "false", "Username and password do not match");
						return;
					}
				}else{
					sendToClient("sign-in", "false", "Username does not exist");
					return;
				}
				break;
			}
			case "sign-up":{
				if(false == server.users.containsKey(message[1])){
					server.users.put(message[1], message[2]);
					sendToClient("sign-up","true","Registration successfully!");
				}else{
					sendToClient("sign-up", "false", "Username exists.");
				}
				return;
			}
			default: return;
			}
			SimpleDateFormat dFormat = new SimpleDateFormat("hh:mm");
			while(true){
				message = getFromClient();
				switch(message[0]){
				case "send-message":{
					server.messages.add(new Message(username, new Date(), message[1]));
					sendToClient("send-message","true","ok!");
					break;
				}
				case "get-message":{
					int offset = Integer.parseInt(message[1]);
					if(offset < -1) offset = -1;
					ArrayList<String> newMessages = new ArrayList<>();
					newMessages.add("get-message");
					for(int i=offset+1; i<server.messages.size();i++){
						newMessages.add(Integer.toString(i));
						newMessages.add(server.messages.get(i).getUsername());
						newMessages.add(dFormat.format(server.messages.get(i).getTimestamp()));
						newMessages.add(server.messages.get(i).getContent());
					}
					if(newMessages.size() < 1){
						out.writeBytes("\n");
					}
					sendToClient(newMessages.toArray(new String[newMessages.size()]));
					break;
				}
				default: return;
				}
			}



		} catch (Exception e) {
			try {
				socket.close();
				e.printStackTrace();
				return;
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}

}
