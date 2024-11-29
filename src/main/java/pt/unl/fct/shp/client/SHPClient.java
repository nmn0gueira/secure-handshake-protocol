package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.AbstractSHPPeer;


import java.io.*;
import java.net.Socket;

public class SHPClient extends AbstractSHPPeer {

    private Socket socket;


    public SHPClient(String request) throws IOException {
        this.socket = new Socket("localhost", 8080);
        this.output = socket.getOutputStream();
        this.input = socket.getInputStream();

        init();

        long timeout = System.currentTimeMillis() + TIMEOUT_MS;

        while (!socket.isClosed() && System.currentTimeMillis() < timeout) {

            try {
                // wait for server response
                byte[] response = new byte[1024];
                int bytesRead = input.read(response);

                byte[] actualData = Utils.subArray(response, 0, bytesRead);
                byte[][] message = extractHeaderAndPayload(actualData);
                MsgType msgType = getMessageType(message[0]);

                handleMessage(msgType, message[1]);

                Thread.sleep(1000);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                e.printStackTrace();
                break;
            }

        }
    }

    @Override
    protected void init() {
        byte[] header = getMessageHeader(MsgType.TYPE_1);
        byte[] userId = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte[] message = Utils.concat(header, userId);
        try {
            output.write(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void handleMessage(MsgType msgType, byte[] bytes) {
        switch (msgType) {
            case TYPE_2 -> {}
            case TYPE_4 -> {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
            default -> {
                throw new IllegalStateException("Unexpected message type: " + msgType); // Should not happen
            }
        }
    }
}
