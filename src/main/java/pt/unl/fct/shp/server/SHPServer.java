package pt.unl.fct.shp.server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class SHPServer {
    int port;

    public SHPServer(int port){
        this.port = port;

    }

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(port)){
            System.out.println("Server is listening on port " + port);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("New client connected");
            }
        } catch (IOException ex){
            System.out.println("Server exception:" + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private void handleClient(Socket socket) throws IOException {
        try (InputStream input = socket.getInputStream();
             OutputStream output = socket.getOutputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(input));
             PrintWriter writer = new PrintWriter(output, true)){

            Boolean handshakeDone = false;

            while (!handshakeDone) {
                //waits client message
                String clientMessage = reader.readLine();
                if (clientMessage == null) {
                    System.out.println("Client disconnected during handshake");
                    socket.close();
                    return;
                }
                System.out.println("Received: " + clientMessage);
                switch (clientMessage) {
                    case "SHP: HELLOW":
                        System.out.println("Sent handshake initiation");
                        break;
                }
            }
        }

    }





}
