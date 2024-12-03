package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.ShpCryptoSpec;
import pt.unl.fct.shp.AbstractShpPeer;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;


public class ShpClient extends AbstractShpPeer {

    private final Socket socket;
    private final String request;
    private static final String USER_ID = "userId";
    private static final String PASSWORD = "password";
    private KeyPair keyPair;
    private PublicKey serverPublicKey;
    private static final String SECRET_KEY = "mySecretKey";


    public ShpClient(String request) throws IOException {
        this.socket = new Socket("localhost", PORT);
        this.request = request;
        this.output = socket.getOutputStream();
        this.input = socket.getInputStream();
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

    @Override
    protected boolean isConnectionClosed() {
        return socket.isClosed();
    }

    private void handleType2Message(byte[] bytes) {
        LOGGER.info("Received message type 2");

        byte[] header = getMessageHeader(MsgType.TYPE_3);

        // Nonce 1 and 2 that will be used for PBE
        byte[] salt = Utils.subArray(bytes, 0, ShpCryptoSpec.SALT_SIZE - 1);
        int iterationCount = ByteBuffer.wrap(bytes, ShpCryptoSpec.SALT_SIZE, ShpCryptoSpec.ITERATION_COUNTER_SIZE).getInt();

        // Nonce 3 and its increment for the next message
        long serverNonce = ByteBuffer.wrap(bytes,
                ShpCryptoSpec.SALT_SIZE + ShpCryptoSpec.ITERATION_COUNTER_SIZE - 1,
                ShpCryptoSpec.NONCE_SIZE).getLong();
        byte[] incrementedServerNonce = ByteBuffer.allocate(Long.BYTES).putLong(serverNonce + 1).array();

        // Nonce 4 and UDP port that will be used for the next message
        byte[] clientNonce = new byte[ShpCryptoSpec.NONCE_SIZE];
        ShpCryptoSpec.SECURE_RANDOM.nextBytes(clientNonce);
        byte[] udpPort = ByteBuffer.allocate(Integer.BYTES).putInt(PORT).array();

        byte[] data = Utils.concat(request.getBytes(), USER_ID.getBytes(), incrementedServerNonce, clientNonce, udpPort);

        try {
            byte[] encryptedData = ShpCryptoSpec.encrypt(data, PASSWORD, salt, iterationCount);

            //Digital Signature
            KeyPair keyPairDH = ShpCryptoSpec.generateDHKeyPair();
            byte[] ydhClient = ShpCryptoSpec.generateYdhClient(keyPairDH);
            KeyPair keyPair = ShpCryptoSpec.generateECDSAKeyPair();
            PrivateKey clientPrivateKey = keyPair.getPrivate();
            byte[] digitalSig = ShpCryptoSpec.sign(clientPrivateKey, data);
            
            byte[] message = Utils.concat(header, encryptedData, ydhClient, digitalSig);
            byte[] hmac = ShpCryptoSpec.generateHMAC(SECRET_KEY.getBytes(), message);
            output.write(hmac);

        } catch (IOException | GeneralSecurityException e) {
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

    protected void runProtocol() {
        init();
        super.runProtocol();
    }


    @Override
    protected void loadResources() {
        try {
            keyPair = ShpCryptoSpec.loadKeyPairFromFile("client/ClientECCKeyPair.sec");
            serverPublicKey = ShpCryptoSpec.loadPublicKeyFromFile("client/ServerECCPublicKey.txt");
        } catch (IOException | GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Failed to load client resources.", e);
        }

    }
}
