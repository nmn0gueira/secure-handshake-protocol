package pt.unl.fct.shp.client;

import pt.unl.fct.common.CommonUtils;
import pt.unl.fct.shp.common.SHProtocol;

import java.io.*;
import java.net.Socket;

public class SHPClient {

    private Socket socket;
    private OutputStream output;
    private InputStream input;


    public SHPClient() throws IOException {
        this.socket = new Socket("localhost", 8080);
        this.output = socket.getOutputStream();
        this.input = socket.getInputStream();

        startHandshake();

        long timeout = System.currentTimeMillis() + SHProtocol.TIMEOUT_MS;

        while (!socket.isClosed() && System.currentTimeMillis() < timeout) {

            try {
                // wait for server response
                byte[] response = new byte[1024];
                int bytesRead = input.read(response);

                byte[] actualData = CommonUtils.subArray(response, 0, bytesRead);
                byte[][] message = SHProtocol.extractHeaderAndPayload(actualData);
                SHProtocol.MsgType msgType = SHProtocol.getMessageType(message[0]);

                handleServerMessage(msgType, message[1]);

                Thread.sleep(1000);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                e.printStackTrace();
                break;
            }

        }
    }

    private void handleServerMessage(SHProtocol.MsgType msgType, byte[] bytes) throws IOException {
        switch (msgType) {
            case TYPE_2 -> {}
            case TYPE_4 -> {
                socket.close();
            }
            default -> {
                throw new IllegalStateException("Unexpected message type: " + msgType); // Should not happen
            }
        }
    }

    /**
     * Starts handshake with the server. This means sending the userId to the server
     * @throws IOException
     */
    private void startHandshake() throws IOException {
        byte[] header = SHProtocol.getMessageHeader(SHProtocol.MsgType.TYPE_1);
        byte[] userId = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte[] message = CommonUtils.concat(header, userId);
        output.write(message);
    }


}
