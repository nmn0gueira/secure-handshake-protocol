package pt.unl.fct.shp;

import org.junit.Test;
import pt.unl.fct.shp.client.ShpClientOutput;
import pt.unl.fct.shp.client.ShpClient;
import pt.unl.fct.shp.server.ShpServerOutput;
import pt.unl.fct.shp.server.ShpServer;

import java.util.HashSet;
import java.util.Set;

public class ShpTest {

    @Test
    public void shp() throws InterruptedException {
        int tcpPort = 7777;

        new Thread(() -> {
            try {
                Set<String> requests = new HashSet<>();
                requests.add("request");
                ShpServer shpServer = new ShpServer();
                ShpServerOutput sOutput = shpServer.shpServer(tcpPort, requests);
                System.out.println("User request received: " + sOutput.request());
                System.out.println("Udp port received: " + sOutput.udpPort());
                System.out.println("Server thread finished");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        Thread.sleep(1000);
        ShpClient shpClient = new ShpClient();
        ShpClientOutput cOutput = shpClient.shpClient("localhost", tcpPort, "userId", "password","request",190);
        System.out.println("Crypto config received:\n" + cOutput.cryptoConfig());
        System.out.println("Client thread finished");
        System.out.println("Sleeping for 5 seconds to allow server to finish");
        Thread.sleep(5000);
    }
}
