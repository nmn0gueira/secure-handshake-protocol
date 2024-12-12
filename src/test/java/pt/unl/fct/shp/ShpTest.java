package pt.unl.fct.shp;

import org.junit.Test;
import pt.unl.fct.common.Utils;
import pt.unl.fct.dstp.SecureDatagramSocket;
import pt.unl.fct.shp.client.ShpClientOutput;
import pt.unl.fct.shp.client.ShpClient;
import pt.unl.fct.shp.server.ShpServerOutput;
import pt.unl.fct.shp.server.ShpServer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.Set;

public class ShpTest {
    private static final int TCP_PORT = 7777;
    private static final int UDP_PORT = 8888;
    private static final String SERVER_CRYPTO_CONFIG_PATH = "server/ciphersuite.conf";


    @Test
    public void shpTest() throws InterruptedException {
        new Thread(() -> {
            try {
                Set<String> requests = new HashSet<>();
                requests.add("request");
                ShpServer shpServer = new ShpServer(SERVER_CRYPTO_CONFIG_PATH);
                ShpServerOutput sOutput = shpServer.shpServer(TCP_PORT, requests);
                System.out.println("User request received: " + sOutput.request());
                System.out.println("Udp port received: " + sOutput.udpPort());
                System.out.println("Shared key received:\n" + Utils.byteArrayToHexString(sOutput.sharedSecret()));
                System.out.println("Server thread finished");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        Thread.sleep(1000);
        ShpClient shpClient = new ShpClient();
        ShpClientOutput cOutput = shpClient.shpClient("localhost", TCP_PORT, "userId", "password","request",UDP_PORT);
        System.out.println("Crypto config received:\n" + cOutput.cryptoConfig());
        System.out.println("Shared key received:\n" + Utils.byteArrayToHexString(cOutput.sharedSecret()));
        System.out.println("Client thread finished");
        System.out.println("Sleeping for 5 seconds to allow server to finish");
        Thread.sleep(5000);
    }

    @Test
    public void shpAndDstpTest() throws InterruptedException, IOException {
        new Thread(() -> {
            try {
                ShpClient shpClient = new ShpClient();
                ShpClientOutput cOutput = shpClient.shpClient("localhost", TCP_PORT, "userId", "password","request", UDP_PORT);

                byte[] message = "Hello, Secure World!".getBytes();
                Thread.sleep(1000);
                SecureDatagramSocket dstpClient = new SecureDatagramSocket(cOutput.cryptoConfig(), cOutput.sharedSecret());
                DatagramPacket sendPacket = new DatagramPacket(
                        message, message.length, InetAddress.getLocalHost(), UDP_PORT);
                dstpClient.send(sendPacket);
                System.out.println("Client thread finished");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        Thread.sleep(1000);

        Set<String> requests = new HashSet<>();
        requests.add("request");
        ShpServer shpServer = new ShpServer(SERVER_CRYPTO_CONFIG_PATH);
        ShpServerOutput sOutput = shpServer.shpServer(TCP_PORT, requests);
        // DSTP
        SecureDatagramSocket dstpServer = new SecureDatagramSocket(sOutput.udpPort(), sOutput.cryptoConfig(), sOutput.sharedSecret());

        DatagramPacket receivePacket = new DatagramPacket(new byte[1024], 1024);
        dstpServer.receive(receivePacket);
        byte[] receivedData = new byte[receivePacket.getLength()];
        System.arraycopy(receivePacket.getData(), receivePacket.getOffset(), receivedData, 0, receivePacket.getLength());
        System.out.println(new String(receivedData));
        System.out.println("Received message: " + new String(receivePacket.getData()));
        System.out.println("Server thread finished");
    }
}
