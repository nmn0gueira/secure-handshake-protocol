package pt.unl.fct.main;

import pt.unl.fct.dstp.SecureDatagramSocket;

import java.net.DatagramPacket;
import java.net.InetAddress;

public class DstpSender {
    public static void main(String[] args) throws Exception {
        InetAddress address = InetAddress.getByName("localhost");
        SecureDatagramSocket socket = new SecureDatagramSocket("cryptoconfig.txt");
        String message = "Hello, World!";

        while (true) {
            byte[] buffer = message.getBytes();
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, 12345);
            System.out.println("Sending packet to " + address.getHostAddress() + " on port " + packet.getPort());
            socket.send(packet);
            Thread.sleep(1000);
        }
        //socket.close();
    }
}

