package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.crypto.CryptoUtils;
import pt.unl.fct.shp.AbstractSHPPeer;


import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;


public class SHPClient extends AbstractSHPPeer {

    private final Socket socket;
    private final String request;
    private static final String USER_ID = "userId";
    private static final String SECRET_KEY = "mySecretKey";

    private static final Logger LOGGER = Logger.getLogger(SHPClient.class.getName());


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
            LOGGER.severe("Error sending message type 1");
        }
    }


    @Override
    protected void handleMessage(MsgType msgType, byte[] bytes) {
        switch (msgType) {
            case TYPE_2 -> handleType2Message(bytes);
            case TYPE_4 -> handleType4Message(bytes);
            default -> {
                LOGGER.severe("Unexpected message type: " + msgType);
                throw new IllegalStateException("Unexpected message type: " + msgType); // Should not happen
            }
        }
    }

    private void handleType2Message(byte[] bytes) {
        LOGGER.info("Received message type 2");

        byte[] header = getMessageHeader(MsgType.TYPE_3);

        byte[] salt = Utils.subArray(bytes, 0, 7);
        int iterationCount = ByteBuffer.wrap(bytes, 8, 4).getInt();
        byte[] nonce3 = Utils.subArray(bytes, 11, 27);
        byte[] password = "password".getBytes();
        byte[] nonce4 = new byte[16];
        CryptoUtils.SECURE_RANDOM.nextBytes(nonce4);

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
        try {

            byte[] pbeh = CryptoUtils.encrypt(data, "password", salt, iterationCount);

            //Digital Signature
            KeyPair keyPairDH = CryptoUtils.generateDHKeyPair();
            byte[] ydhClient = CryptoUtils.generateYdhClient(keyPairDH);
            KeyPair keyPair = CryptoUtils.generateKeyPair();
            PrivateKey clientPrivateKey = keyPair.getPrivate();
            byte[] digitalSig = CryptoUtils.sign(clientPrivateKey, data);
            
            byte[] message = Utils.concat(header, pbeh, ydhClient, digitalSig);
            byte[] hmac = CryptoUtils.generateHMAC(SECRET_KEY.getBytes(), message);
            output.write(hmac);

        } catch (Exception e) {
            LOGGER.severe("Error sending message type 3");
            throw new RuntimeException(e);
        }
    }

    private void handleType4Message(byte[] bytes) {
        LOGGER.info("Received message type 4");
        try {
            socket.close();
        } catch (IOException e) {
            LOGGER.severe("Error closing socket");
        }
    }

    @Override
    protected void runProtocol() {
        init();
        long timeout = System.currentTimeMillis() + TIMEOUT_MS;

        while (!socket.isClosed() && System.currentTimeMillis() < timeout) {
            try {
                if (!processServerMessage()) {
                    LOGGER.warning("Server finished.");
                    break;
                }
                timeout = System.currentTimeMillis() + TIMEOUT_MS;

                Thread.sleep(1000);
            } catch (InterruptedException e) {
                LOGGER.warning("Server interrupted.");
                Thread.currentThread().interrupt();
                break;
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error during protocol execution.", e);
                throw new RuntimeException(e);
            }
        }
    }

    private boolean processServerMessage() throws IOException {
        byte[] response = new byte[1024];
        int bytesRead = input.read(response);

        if (bytesRead == -1) {
            LOGGER.info("Client closed connection.");
            return false;
        }
        if (bytesRead == 0) {
            return true; // Keep the connection alive on empty reads
        }

        byte[] actualData = Utils.subArray(response, 0, bytesRead);
        byte[][] message = extractHeaderAndPayload(actualData);
        MsgType msgType = getMessageType(message[0]);

        handleMessage(msgType, message[1]);

        return msgType != MsgType.TYPE_5;   // Return false if the server should finish
    }


    @Override
    protected void loadResources() {

    }
}
