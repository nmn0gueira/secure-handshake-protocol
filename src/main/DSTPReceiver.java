package main;

import dstp.SecureDatagramSocket;

import java.net.DatagramPacket;

public class DSTPReceiver {
    public static void main(String[] args) throws Exception {
        SecureDatagramSocket socket = new SecureDatagramSocket(12345, "cryptoconfig.txt");
        System.out.println("Listening on port " + socket.getLocalPort());

        while (true) {
            byte[] buffer = new byte[1024];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

            socket.receive(packet);
            System.out.print("Received packet: ");
            System.out.println(new String(packet.getData()));
        }

        // socket.close();
    }
}
