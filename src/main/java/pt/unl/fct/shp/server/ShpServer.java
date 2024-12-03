package pt.unl.fct.shp.server;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.AbstractShpPeer;
import pt.unl.fct.shp.ShpCryptoSpec;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

public class ShpServer extends AbstractShpPeer {

    private final Map<String, User> userDatabase;
    private final ServerSocket serverSocket;
    private Socket clientSocket;
    KeyPair keyPair;

    public ShpServer() throws IOException {
        userDatabase = new HashMap<>();
        this.serverSocket = new ServerSocket(PORT);
        LOGGER.info("Server is listening on port " + PORT);
        loadResources();
        runProtocol();
    }

    @Override
    protected void loadResources() {
        try {
            keyPair = ShpCryptoSpec.loadKeyPairFromFile("server/ServerECCKeyPair.sec");
            loadUserDatabase();
        } catch (IOException | GeneralSecurityException e) {
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
            userDatabase.put(userId, new User(userId, passwordHash, salt, ShpCryptoSpec.loadPublicKey(publicKeyBytes)));
        }
    }

    @Override
    protected void runProtocol() {
        try {
            acceptClientConnection();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to accept client connection.", e);
        }
        super.runProtocol();
    }

    @Override
    protected boolean isConnectionClosed() {
        return clientSocket == null || clientSocket.isClosed();
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

        byte[] salt = new byte[ShpCryptoSpec.SALT_SIZE];
        ShpCryptoSpec.SECURE_RANDOM.nextBytes(salt);
        byte[] iterationBytes = new byte[ShpCryptoSpec.ITERATION_COUNTER_SIZE];
        ShpCryptoSpec.SECURE_RANDOM.nextBytes(iterationBytes);
        byte[] nonce = new byte[ShpCryptoSpec.NONCE_SIZE];
        ShpCryptoSpec.SECURE_RANDOM.nextBytes(nonce);

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
        try {
            byte[] nonce5 = new byte[ShpCryptoSpec.NONCE_SIZE];
            byte[] encryptedData = Utils.subArray(bytes, 0,);
            byte[] ydhClient = Utils.subArray(bytes, );
            byte[] digitalSig = Utils.subArray(bytes,);
            byte[] hmac = Utils.subArray(bytes, );
            String userId = new String(bytes);

            if (!userDatabase.containsKey(userId)) {
                LOGGER.warning("User not found.");
                return;
            }

            // HMAC validation
            byte[] expectedHMAC = ShpCryptoSpec.generateHMAC(SECRET_KEY.getBytes(), Utils.subArray(bytes, 0, bytes.length - hmac.length));
            if (!MessageDigest.isEqual(hmac, expectedHMAC)) {
                LOGGER.warning("Invalid HMAC.");
                return;
            }

            // Validate Digital Signature using the client publickey
            boolean isSignatureValid = ShpCryptoSpec.verify(user.publicKey(), encryptedData, digitalSig);
            if (!isSignatureValid) {
                LOGGER.warning("Invalid digital signature.");
                return;
            }

            // Generate DH secret
            KeyPair serverDHKeyPair = ShpCryptoSpec.generateDHKeyPair();
            byte[] sharedSecret = ShpCryptoSpec.generateSharedSecret(serverDHKeyPair.getPrivate(), ydhClient);


        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error processing TYPE_3 message.", e);
        }
    }
        }
    }

}
