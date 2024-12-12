package pt.unl.fct.shp.server;

import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.HashUtils;
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

    // Server resources
    private static final String SERVER_ECC_KEYPAIR_PATH = "server/ServerECCKeyPair.sec";
    private Map<String, User> userDatabase;
    private byte[] cryptoConfigBytes;
    private ShpCryptoSpec serverCryptoSpec;
    private ServerSocket serverSocket;

    // Current client connection
    private Socket clientSocket;
    private User currentUser;

    // Protocol parameters
    private Set<String> validRequests;

    // Protocol output
    private String userRequest;
    private int udpPort;
    private byte[] sharedSecret;


    public ShpServer(String serverCryptoConfigPath) {
        loadServerResources(serverCryptoConfigPath);
    }

    public ShpServerOutput shpServer(int tcpPort, Set<String> validRequests) {
        setInitInput(validRequests);
        State state = runProtocolServer(tcpPort);
        if (state != State.FINISHED) {
            throw new IllegalStateException("Protocol did not finish successfully.");
        }
        return new ShpServerOutput(userRequest, udpPort, new String(cryptoConfigBytes), sharedSecret);
    }

    private void setInitInput(Set<String> validRequests) {
        this.validRequests = validRequests;
    }

    protected State runProtocolServer(int tcpPort) {
        try {
            startListening(tcpPort);
            acceptClientConnection();
            return super.runProtocol();
        } finally {
            closeConnection();
            serverCryptoSpec.reset();   // Reset the crypto spec to avoid reusing the same init parameters
            noncesReceived.clone();     // Clear the set of received nonces
        }
    }

    private void startListening(int tcpPort) {
        try {
            serverSocket = new ServerSocket(tcpPort);
            LOGGER.info("Server started listening on port " + tcpPort);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to start server socket.", e);
        }
    }

    private void acceptClientConnection()  {
        try {
            clientSocket = serverSocket.accept();
            output = new ObjectOutputStream(clientSocket.getOutputStream());
            input = new ObjectInputStream(clientSocket.getInputStream());
            LOGGER.info("Client connected.");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to accept client connection.", e);
        }
    }

    private void closeConnection() {
        try {
            closeStreams();
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to close server connection resources.", e);
        }
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

        byte[] salt = serverCryptoSpec.generateShpNonce();
        byte[] iterationBytes = serverCryptoSpec.generateShpIterationBytes();
        byte[] nonce = serverCryptoSpec.generateShpNonce();

        // Initialize cryptographic constructions for this user
        serverCryptoSpec.initIntegrityCheck(currentUser.passwordHash());
        serverCryptoSpec.initPbeCipher(
                new String(currentUser.passwordHash()),
                Utils.fitToSize(salt, ShpCryptoSpec.SALT_SIZE),
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
            byte[] sharedSecret = serverCryptoSpec.generateSharedSecret(ydhClient);
            serverCryptoSpec.initSharedKeyCipher(HashUtils.SHA3_256.digest(sharedSecret));

            byte[] confirmation = ShpCryptoSpec.REQUEST_CONFIRMATION.getBytes();
            byte[] incrementedClientNonce = Utils.getIncrementedBytes(clientNonce);
            byte[] newServerNonce = serverCryptoSpec.generateShpNonce();

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

            // Assign output values
            this.userRequest = new String(requestBytes);
            this.udpPort = ((udpPortBytes[0] & 0xFF) << 24) | ((udpPortBytes[1] & 0xFF) << 16) | ((udpPortBytes[2] & 0xFF) << 8) | (udpPortBytes[3] & 0xFF);
            this.sharedSecret = sharedSecret;

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

    @Override
    protected boolean isConnectionClosed() {
        return clientSocket == null || clientSocket.isClosed();
    }

    protected void loadServerResources(String serverCryptoConfigPath) {
        try {
            loadUserDatabase();
            loadCryptoConfig(serverCryptoConfigPath);
            this.serverCryptoSpec = new ShpCryptoSpec(SERVER_ECC_KEYPAIR_PATH);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to load server resources.", e);
        }
    }

    private void loadUserDatabase() throws IOException {
        this.userDatabase = new HashMap<>();
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
            this.userDatabase.put(userId, new User(userId, passwordHash, salt, ShpCryptoSpec.loadPublicKey(publicKeyBytes)));
        }
    }

    private void loadCryptoConfig(String serverCryptoConfigPath) throws IOException {
        // Try to first load the file from the resources
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream(serverCryptoConfigPath)) {
            if (inputStream != null) {
                cryptoConfigBytes = inputStream.readAllBytes();
                return;
            }
        }
        // If the file is not found in the resources, try to load it from the file system
        try (InputStream inputStream = new FileInputStream(serverCryptoConfigPath)) {
            cryptoConfigBytes = inputStream.readAllBytes();
            if (cryptoConfigBytes.length == 0) {
                throw new FileNotFoundException("Crypto config file not found.");
            }
        }
    }
}
