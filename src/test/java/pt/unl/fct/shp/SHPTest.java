package pt.unl.fct.shp;

import org.junit.Test;
import pt.unl.fct.shp.client.ShpClient;
import pt.unl.fct.shp.server.ShpServer;

import java.io.IOException;
import java.security.InvalidKeyException;

public class SHPTest {

    @Test
    public void SHP() throws IOException, InterruptedException, InvalidKeyException {
        new Thread(() -> {
            try {
                new ShpServer();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        Thread.sleep(1000);
        new ShpClient("request");
    }
}
