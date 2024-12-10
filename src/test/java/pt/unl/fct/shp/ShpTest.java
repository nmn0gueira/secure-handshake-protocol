package pt.unl.fct.shp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import pt.unl.fct.shp.client.ShpClient;
import pt.unl.fct.shp.server.ShpServer;

import java.io.IOException;
import java.security.Security;

public class ShpTest {

    @Test
    public void shp() throws IOException, InterruptedException {
        Security.addProvider(new BouncyCastleProvider());
        new Thread(() -> {
            try {
                new ShpServer(null);
                System.out.println("Server thread finished");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        Thread.sleep(1000);
        new ShpClient("request");
        System.out.println("Client thread finished");
    }
}
