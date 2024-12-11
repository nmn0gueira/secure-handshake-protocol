package pt.unl.fct.shp.server;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.AbstractShpPeer;
import pt.unl.fct.shp.crypto.ShpCryptoSpec;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

public class ShpServer extends AbstractShpPeer {

    private static final String SERVER_ECC_KEYPAIR_PATH = "server/ServerECCKeyPair.sec";
    private static final String SERVER_CRYPTO_CONFIG_PATH = "server/ciphersuite.conf";
    private final Map<String, User> userDatabase;
    private final Set<String> validRequests;
    private final ShpCryptoSpec serverCryptoSpec;
    private final ServerSocket serverSocket;
    private Socket clientSocket;
    private User currentUser;
    private byte[] cryptoConfigBytes;
    private String userRequest;
    private int udpPort;


    /**
     * Creates a new SHP server.
     *
     * @throws IOException - if an I/O error occurs when creating the ServerSocket.
     */
    public ShpServer(Set<String> validRequests) throws IOException {
        userDatabase = new HashMap<>();
        this.validRequests = validRequests;
        this.serverSocket = new ServerSocket(TCP_PORT);
        this.serverCryptoSpec = new ShpCryptoSpec(SERVER_ECC_KEYPAIR_PATH);
        LOGGER.info("Server is listening on port " + TCP_PORT);
        loadResources();

    }

    public ServerOutput startServer() {
        runProtocol();
        if (userRequest == null || udpPort == 0) {
            throw new IllegalStateException("User request and UDP port were not set.");
        }
        return new ServerOutput(userRequest, udpPort);
    }

    @Override
    protected void loadResources() {
        try {
            loadUserDatabase();
            loadCryptoConfig();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to load server resources.", e);
        }
    }

    private void loadUserDatabase() throws IOException {
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

    private void loadCryptoConfig() throws IOException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(SERVER_CRYPTO_CONFIG_PATH);
        assert inputStream != null;
        cryptoConfigBytes = inputStream.readAllBytes();
    }

    @Override
    protected State runProtocol() {
        try {
            acceptClientConnection();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to accept client connection.", e);
        }
        return super.runProtocol();
    }

    @Override
    protected boolean isConnectionClosed() {
        return clientSocket == null || clientSocket.isClosed();
    }

    private void acceptClientConnection() throws IOException {
        clientSocket = serverSocket.accept();
        input = new ObjectInputStream(clientSocket.getInputStream());
        output = new ObjectOutputStream(clientSocket.getOutputStream());
        LOGGER.info("Client connected.");
    }

    @Override
    protected State handleMessage(MsgType msgType, List<byte[]> payload) {
        switch (msgType) {
            case TYPE_1 -> {
                return handleType1Message(payload);
            }
            case TYPE_3 -> {
                return handleType3Message(payload);
            }
            case TYPE_5 -> {
                return handleType5Message(payload);
            }
            default -> {
                LOGGER.severe("Unexpected message type: " + msgType);
                return State.ERROR;
            }
        }
    }

    private State handleType1Message(List<byte[]> payload) {
        LOGGER.info("Received message type 1.");

        String userId = new String(payload.getFirst());
        currentUser = userDatabase.get(userId);
        if (currentUser == null) {
            LOGGER.warning("User not found.");
            return State.ERROR;
        }

        byte[] salt = ShpCryptoSpec.generateShpNonce();
        byte[] iterationBytes = ShpCryptoSpec.generateShpIterationBytes();
        byte[] nonce = ShpCryptoSpec.generateShpNonce();

        // Initialize cryptographic constructions for this user
        serverCryptoSpec.initIntegrityCheck(currentUser.passwordHash());
        serverCryptoSpec.initPbeCipher(
                new String(currentUser.passwordHash()),
                Utils.getFirstBytes(salt, ShpCryptoSpec.SALT_SIZE),
                ((iterationBytes[0] & 0xFF) << 8) | (iterationBytes[1] & 0xFF));

        byte[] header = getMessageHeader(MsgType.TYPE_2);

        try {
            output.writeObject(createShpMessage(header, salt, iterationBytes, nonce));
            LOGGER.info("Sent TYPE_2 response.");
            return State.ONGOING;
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error sending message TYPE_2.", e);
            return State.ERROR;
        }
    }

    private State handleType3Message(List<byte[]> payload) {
        LOGGER.info("Received message type 3.");


        byte[] passwordEncryptedData = payload.get(0);
        byte[] ydhClient = payload.get(1);
        byte[] clientSignature = payload.get(2);
        byte[] integrityProofReceived = payload.get(3);

        byte[] dataToVerify = Utils.concat(passwordEncryptedData, ydhClient, clientSignature);

        try {

            if (!serverCryptoSpec.verifyIntegrity(dataToVerify, integrityProofReceived)) {
                LOGGER.severe("Message has been tampered with");
                return State.ERROR;
            }

            byte[] decryptedData = serverCryptoSpec.passwordBasedDecrypt(passwordEncryptedData);

            PublicKey clientPublicKey = currentUser.publicKey();

            byte[] signatureData = Utils.concat(decryptedData, ydhClient);
            if (!serverCryptoSpec.verifySignature(clientPublicKey, signatureData, clientSignature)) {
                LOGGER.severe("Invalid client digital signature.");
                return State.ERROR;
            }

            int userIdLength = currentUser.userId().getBytes().length;

            // These offsets delimit where each component of the data starts
            // The first component (which has offset 0) is the request received (which has variable length)
            int userIdOffset = decryptedData.length - userIdLength - 2 * ShpCryptoSpec.NONCE_SIZE -
                    Integer.BYTES;
            int firstNonceOffset = userIdOffset + userIdLength;
            int secondNonceOffset = firstNonceOffset + ShpCryptoSpec.NONCE_SIZE;
            int udpPortOffset = secondNonceOffset + ShpCryptoSpec.NONCE_SIZE;

            byte[][] dataParts = Utils.divideInParts(
                    decryptedData,
                    userIdOffset,
                    firstNonceOffset,
                    secondNonceOffset,
                    udpPortOffset
            );

            byte[] requestBytes = dataParts[0];
            byte[] userId = dataParts[1];
            byte[] incrementedServerNonce = dataParts[2];
            byte[] clientNonce = dataParts[3];
            byte[] udpPortBytes = dataParts[4];

            if (!new String(userId).equals(currentUser.userId())) {
                LOGGER.severe("Invalid user ID.");
                return State.ERROR;
            }

            if (!validRequests.contains(new String(requestBytes))) {
                LOGGER.severe("Invalid request.");
                return State.ERROR;
            }

            if (!(noncesReceived.add(incrementedServerNonce) && noncesReceived.add(clientNonce))) {
                LOGGER.severe("Invalid nonce.");
                return State.ERROR;
            }

            // Initialize the shared key cipher
            byte[] sharedKey = serverCryptoSpec.generateSharedKey(ydhClient);
            serverCryptoSpec.initSharedKeyCipher(sharedKey);

            byte[] confirmation = ShpCryptoSpec.REQUEST_CONFIRMATION.getBytes();
            byte[] incrementedClientNonce = Utils.getIncrementedBytes(clientNonce);
            byte[] newServerNonce = ShpCryptoSpec.generateShpNonce();

            byte[] publicKeyEncryptedData = serverCryptoSpec.asymmetricEncrypt(
                    Utils.concat(confirmation, incrementedClientNonce, newServerNonce, cryptoConfigBytes),
                    clientPublicKey
            );

            byte[] ydhServer = serverCryptoSpec.getYdhBytes();

            byte[] digitalSignature = serverCryptoSpec.sign(Utils.concat(
                    confirmation,
                    currentUser.userId().getBytes(),
                    incrementedClientNonce,
                    newServerNonce,
                    cryptoConfigBytes,
                    ydhServer));

            byte[] integrityProof = serverCryptoSpec.createIntegrityProof(Utils.concat(publicKeyEncryptedData, ydhServer, digitalSignature));

            byte[] header = getMessageHeader(MsgType.TYPE_4);

            userRequest = new String(requestBytes);
            // Extract the UDP port from the received bytes
            udpPort = ((udpPortBytes[0] & 0xFF) << 24) | ((udpPortBytes[1] & 0xFF) << 16) | ((udpPortBytes[2] & 0xFF) << 8) | (udpPortBytes[3] & 0xFF);

            output.writeObject(createShpMessage(header, publicKeyEncryptedData, ydhServer, digitalSignature, integrityProof));
            LOGGER.info("Sent TYPE_4 response.");
            return State.ONGOING;

        } catch (IOException | GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error processing TYPE_3 message.", e);
            return State.ERROR;
        }
    }

    private State handleType5Message(List<byte[]> payload){
        LOGGER.info("Received message type 5.");

        byte[] sharedKeyEncryptedData = payload.get(0);
        byte[] integrityProofReceived = payload.get(1);

        try {
            if (!serverCryptoSpec.verifyIntegrity(sharedKeyEncryptedData, integrityProofReceived)) {
                LOGGER.severe("Message has been tampered with");
                return State.ERROR;
            }

            byte[] decryptedData = serverCryptoSpec.sharedKeyDecrypt(sharedKeyEncryptedData);

            byte[][] dataParts = Utils.divideInParts(decryptedData, ShpCryptoSpec.FINISH_PROTOCOL.getBytes().length);

            byte[] finishProtocol = dataParts[0];

            byte[] incrementedNonce = dataParts[1];

            if (!new String(finishProtocol).equals(ShpCryptoSpec.FINISH_PROTOCOL)) {
                LOGGER.severe("Invalid finish protocol message.");
                return State.ERROR;
            }

            if (!noncesReceived.add(incrementedNonce)) {
                LOGGER.severe("Invalid nonce.");
                return State.ERROR;
            }

            return State.FINISHED;

        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error processing TYPE_5 message.", e);
            return State.ERROR;
        }
    }

}
