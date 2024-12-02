package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.AbstractSHPPeer;
import pt.unl.fct.shp.cryptoH2.ECDSAUtils;
import pt.unl.fct.shp.cryptoH2.PBEUtils;


import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;


public class SHPClient extends AbstractSHPPeer {

    private final Socket socket;
    private final String request;
    private static final String USER_ID = "userId";

    private static final SecureRandom SECURE_RANDOM =  new SecureRandom();


    public SHPClient(String request) throws IOException {
        this.socket = new Socket("localhost", PORT);
        this.request = request;
        this.output = socket.getOutputStream();
        this.input = socket.getInputStream();
        runProtocol();
    }

    private void init() {
        byte[] header = getMessageHeader(MsgType.TYPE_1);
        byte[] userId = USER_ID.getBytes();
        byte[] message = Utils.concat(header, userId);
        try {
            output.write(message);
        } catch (IOException e) {
            System.out.println("Error sending message type 1");
        }
    }


    @Override
    protected void handleMessage(MsgType msgType, byte[] bytes) {
        switch (msgType) {
            case TYPE_2 -> {
                System.out.println("Received message type 2");
                byte[] header = getMessageHeader(MsgType.TYPE_3);
                byte[] message = Utils.concat(header, bytes);
                try {
                    output.write(message);
                } catch (IOException e) {
                    System.out.println("Error sending message type 3");
                }


            }

            case TYPE_3 -> {
                try {

                    byte[] salt = Utils.subArray(bytes, 0, 7);
                    int iterationCount = ByteBuffer.wrap(bytes, 8, 4).getInt();
                    byte[] nonce3 = Utils.subArray(bytes, 11, 27);
                    byte[] password = "password".getBytes();
                    byte[] nonce4 = new byte[16];
                    SECURE_RANDOM.nextBytes(nonce4);
                    //send data on TYPE_3

                    ByteBuffer buffer = ByteBuffer.wrap(nonce3);

                    // Extraindo o primeiro inteiro
                    int int1 = buffer.getInt(); // Os primeiros 4 bytes como int
                    int1 += 1; // Soma 1 ao primeiro inteiro

                    // Extraindo outros inteiros (se necessário)
                    int int2 = buffer.getInt(); // Próximos 4 bytes
                    int int3 = buffer.getInt(); // Próximos 4 bytes
                    int int4 = buffer.getInt(); // Últimos 4 bytes

                    // colocar os inteiros de volta em um novo array de bytes:
                    ByteBuffer resultBuffer = ByteBuffer.allocate(16);
                    resultBuffer.putInt(int1);
                    resultBuffer.putInt(int2);
                    resultBuffer.putInt(int3);
                    resultBuffer.putInt(int4);

                    byte[] updatedNonce3 = resultBuffer.array(); // Array final com inteiros atualizados

                    byte[] udpPort = ByteBuffer.allocate(4).putInt(PORT).array();
                    byte[] data = Utils.concat(request.getBytes(), USER_ID.getBytes(), updatedNonce3, nonce4, udpPort);
                    byte[] pbeh = PBEUtils.encrypt(data, "password", salt, iterationCount);

                    //Digital Signature
                    KeyPair keyPair = ECDSAUtils.generateKeyPair();
                    PrivateKey clientPrivateKey = keyPair.getPrivate();
                    byte[] digitalSig = ECDSAUtils.sign(clientPrivateKey, data);

                    




                } catch (Exception e) {
                    throw new RuntimeException(e);
                }


            }
            case TYPE_4 -> {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.out.println("Error closing socket");
                }

            }
            default -> {
                throw new IllegalStateException("Unexpected message type: " + msgType); // Should not happen
            }
        }
    }

    @Override
    protected void runProtocol() {
        init();

        long timeout = System.currentTimeMillis() + TIMEOUT_MS;

        while (!socket.isClosed() && System.currentTimeMillis() < timeout) {

            try {
                // wait for server response
                byte[] response = new byte[1024];
                int bytesRead = input.read(response);

                if (bytesRead == -1) {
                    System.out.println("Server closed connection");
                    break;
                }
                if (bytesRead == 0) {
                    timeout = System.currentTimeMillis() + TIMEOUT_MS;
                    continue;
                }

                byte[] actualData = Utils.subArray(response, 0, bytesRead);
                byte[][] message = extractHeaderAndPayload(actualData);
                MsgType msgType = getMessageType(message[0]);

                handleMessage(msgType, message[1]);

                Thread.sleep(1000);

            } catch (InterruptedException e) {
                System.out.println("Client interrupted");
                Thread.currentThread().interrupt();
                break;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        }
    }

    @Override
    protected void loadResources() {

    }
}
