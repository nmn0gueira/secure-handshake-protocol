package pt.unl.fct.shp.server;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.AbstractSHPPeer;
import pt.unl.fct.shp.cryptoH2.ECDSAUtils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SHPServer extends AbstractSHPPeer {

    private static final SecureRandom SECURE_RANDOM =  new SecureRandom();
    private static final Logger LOGGER = Logger.getLogger(SHPServer.class.getName());
    private final Map<String, Map.Entry<byte[], byte[]>> userDatabase;
    private final ServerSocket serverSocket;
    private Socket clientSocket;
    KeyStore keyStore;

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
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            InputStream inputStream = classLoader.getResourceAsStream("server/ServerECCKeyPair.sec");
            PrivateKey privateKey = null;
            PublicKey publicKey = null;
            // Read the file content
            assert inputStream != null;
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(":");
                    if (parts[0].equals("PublicKey")) {
                        publicKey = ECDSAUtils.loadPublicKey(Utils.hexStringToByteArray(parts[1]));
                    } else
                    if (parts[0].equals("PrivateKey")) {
                        privateKey = ECDSAUtils.loadPrivateKey(Utils.hexStringToByteArray(parts[1]));
                    }
                }

            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("serverPrivate", privateKey, null, null);
            keyStore.setKeyEntry("serverPublic", publicKey, null, null);

            inputStream = classLoader.getResourceAsStream("server/userdatabase.txt");
            assert inputStream != null;
            reader = new BufferedReader(new InputStreamReader(inputStream));
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(" ");
                byte[] passwordHash = Utils.hexStringToByteArray(parts[1]);
                byte[] salt = Utils.hexStringToByteArray(parts[2]);
                byte[] publicKeyBytes = Utils.hexStringToByteArray(parts[3]);
                userDatabase.put(parts[0], Map.entry(passwordHash, salt));

                keyStore.setKeyEntry(parts[0], ECDSAUtils.loadPublicKey(publicKeyBytes), null, null);

            }


        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to load server resources.", e);
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

        return true;
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
                throw new IllegalStateException();
            }
        }
    }

    private void handleType1Message(byte[] bytes) {
        LOGGER.info("Received message type 1.");

        byte[] salt = new byte[8];
        SECURE_RANDOM.nextBytes(salt);
        byte[] iterationBytes = new byte[4];
        SECURE_RANDOM.nextBytes(iterationBytes);
        byte[] nonce = new byte[16];
        SECURE_RANDOM.nextBytes(nonce);

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
