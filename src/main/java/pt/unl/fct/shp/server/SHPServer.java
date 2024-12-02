package pt.unl.fct.shp.server;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.AbstractSHPPeer;
import pt.unl.fct.crypto.CryptoUtils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SHPServer extends AbstractSHPPeer {

    private static final Logger LOGGER = Logger.getLogger(SHPServer.class.getName());
    private final Map<String, User> userDatabase;
    private final ServerSocket serverSocket;
    private Socket clientSocket;
    KeyPair keyPair;

    public SHPServer() throws IOException {
        userDatabase = new HashMap<>();
        loadResources();
        this.serverSocket = new ServerSocket(PORT);
        System.out.println("Server is listening on port " + PORT);
        runProtocol();
    }

    @Override
    protected void loadResources() {
        try {
            keyPair = CryptoUtils.loadKeyPairFromFile("server/ServerECCKeyPair.sec");
            loadUserDatabase();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to load server resources.", e);
        }
    }

    private void loadUserDatabase() throws IOException, GeneralSecurityException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("server/userdatabase.txt");
        assert inputStream != null;
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(":");
            String userId = parts[0].trim();
            byte[] passwordHash = Utils.hexStringToByteArray(parts[1].trim());
            byte[] salt = Utils.hexStringToByteArray(parts[2].trim());
            byte[] publicKeyBytes = Utils.hexStringToByteArray(parts[3].trim());
            userDatabase.put(parts[0], new User(parts[0], passwordHash, salt, CryptoUtils.loadPublicKey(publicKeyBytes)));
        }
    }

    @Override
    protected void runProtocol() {
        try {
            acceptClientConnection();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to accept client connection.", e);
        }

        long timeout = System.currentTimeMillis() + TIMEOUT_MS;

        while (!clientSocket.isClosed() && System.currentTimeMillis() < timeout) {
            try {
                if (!processClientMessage()) {
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

    private boolean processClientMessage() throws IOException {
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

    private void acceptClientConnection() throws IOException {
        clientSocket = serverSocket.accept();
        input = clientSocket.getInputStream();
        output = clientSocket.getOutputStream();
        LOGGER.info("Client connected.");
    }

    @Override
    protected void handleMessage(MsgType msgType, byte[] bytes) {
        switch (msgType) {
            case TYPE_1 -> handleType1Message(bytes);
            case TYPE_3 -> handleType3Message(bytes);
            default -> {
                LOGGER.severe(() -> "Unexpected message type: " + msgType);
                throw new IllegalStateException("Unexpected message type: " + msgType);
            }
        }
    }

    private void handleType1Message(byte[] bytes) {
        LOGGER.info("Received message type 1.");

        String userId = new String(bytes);
        if (!userDatabase.containsKey(userId)) {
            LOGGER.warning("User not found.");
            return;
        }

        byte[] salt = new byte[8];
        CryptoUtils.SECURE_RANDOM.nextBytes(salt);
        byte[] iterationBytes = new byte[4];
        CryptoUtils.SECURE_RANDOM.nextBytes(iterationBytes);
        byte[] nonce = new byte[16];
        CryptoUtils.SECURE_RANDOM.nextBytes(nonce);

        byte[] header = getMessageHeader(MsgType.TYPE_2);
        byte[] message = Utils.concat(header, salt, iterationBytes, nonce);

        try {
            output.write(message);
            LOGGER.info("Sent TYPE_2 response.");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error sending message TYPE_2.", e);
        }
    }

    private void handleType3Message(byte[] bytes) {
        LOGGER.info("Received message type 3.");
    }

}
