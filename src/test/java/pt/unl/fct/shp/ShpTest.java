package pt.unl.fct.shp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import pt.unl.fct.shp.client.ShpClient;
import pt.unl.fct.shp.server.ShpServer;

import java.io.IOException;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;

public class ShpTest {

    @Test
    public void shp() throws IOException, InterruptedException {
        Security.addProvider(new BouncyCastleProvider());

        new Thread(() -> {
            try {
                Set<String> requests = new HashSet<>();
                requests.add("request");
                new ShpServer(requests);
                System.out.println("Server thread finished");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        Thread.sleep(1000);
        new ShpClient("userId", "password","request",190);
        System.out.println("Client thread finished");
        Thread.sleep(10000);
    }
}
