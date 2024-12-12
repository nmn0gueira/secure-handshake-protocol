package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.HashUtils;
import pt.unl.fct.shp.crypto.ShpCryptoSpec;
import pt.unl.fct.shp.AbstractShpPeer;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.List;
import java.util.logging.Level;


public class ShpClient extends AbstractShpPeer {

    // Client resources
    private static final String CLIENT_ECC_KEYPAIR_PATH = "client/ClientECCKeyPair.sec";
    private static final String SERVER_ECC_PUBLIC_KEY_PATH = "client/ServerECCPubKey.txt";
    private ShpCryptoSpec clientCryptoSpec;
    private PublicKey serverPublicKey;
    private Socket socket;

    // Protocol parameters
    private String userId;
    private byte[] passwordDigest;
    private String request;
    private byte[] udpPortBytes;

    // Protocol output
    private String cryptoConfig;
    private byte[] sharedSecret;


    public ShpClient() {
        loadClientResources();
    }

    public ShpClientOutput shpClient(String serverAddress, int tcpPort, String userId, String password, String request, int udpPort) {
        setInitInput(userId, password, request, udpPort);
        State state = runProtocolClient(serverAddress, tcpPort);
        if (state != State.FINISHED) {
            throw new IllegalStateException("Client did not finish successfully");
        }
        try { // TODO: This is a workaround to allow the server to finish before the client
            Thread.sleep(2500);
        } catch (InterruptedException e) {
            LOGGER.log(Level.WARNING, "Client thread interrupted.", e);
        }
        return new ShpClientOutput(cryptoConfig, sharedSecret);
    }

    private void setInitInput(String userId, String password, String request, int udpPort) {
        if (userId.getBytes().length > ShpCryptoSpec.USER_ID_MAX_SIZE) {
            throw new IllegalArgumentException("User ID too long");
        }
        this.userId = userId;
        this.passwordDigest = HashUtils.SHA256.digest(password.getBytes());
        this.request = request;
        this.udpPortBytes = ByteBuffer.allocate(Integer.BYTES).putInt(udpPort).array();
        this.clientCryptoSpec.initIntegrityCheck(passwordDigest);
    }

    protected State runProtocolClient(String serverAddress, int tcpPort) {
        try {
            setupConnection(serverAddress, tcpPort);
            initProtocol();
            return super.runProtocol();
        } finally {
            closeConnection();
            clientCryptoSpec.reset();   // Reset the crypto spec to avoid reusing the same init parameters
            noncesReceived.clone();     // Clear the set of received nonces
        }
    }

    private void setupConnection(String serverAddress, int tcpPort) {
        try {
            this.socket = new Socket(serverAddress, tcpPort);
            this.output = new ObjectOutputStream(socket.getOutputStream());
            this.input = new ObjectInputStream(socket.getInputStream());
        } catch (IOException e) {
            LOGGER.severe("Error setting up connection: " + e.getMessage());
        }
    }

    private void initProtocol() {
        byte[] header = getMessageHeader(MsgType.TYPE_1);
        byte[] userId = this.userId.getBytes();
        try {
            output.writeObject(createShpMessage(header, userId));
        } catch (IOException e) {
            LOGGER.severe("Error sending message type 1");
        }
    }

    private void closeConnection() {
        try {
            closeStreams();
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to close client connection resources.", e);
        }
    }

    @Override
    protected State handleMessage(MsgType msgType, List<byte[]> payload) {
        switch (msgType) {
            case TYPE_2 ->  {
                return handleType2Message(payload);
            }
            case TYPE_4 ->  {
                return handleType4Message(payload);
            }
            default -> {
                LOGGER.severe("Unexpected message type: " + msgType);
                return State.ERROR; // Should not happen
            }
        }
    }

    private State handleType2Message(List<byte[]> payload) {
        LOGGER.info("Received message type 2");

        byte[] header = getMessageHeader(MsgType.TYPE_3);

        // Nonce 1 and 2 that will be used for PBE and nonce 3 that will be used for the next message nonce
        byte[] salt = Utils.fitToSize(payload.get(0), ShpCryptoSpec.SALT_SIZE);
        byte[] iterationBytes = payload.get(1);
        byte[] serverNonce = payload.get(2);

        // Check if any of the nonces received is repeated // TODO: This might be unnecessary and also wrong (because of not using the full size nonces for salt and iteration)
        if (!(noncesReceived.add(salt) && noncesReceived.add(iterationBytes) && noncesReceived.add(serverNonce))) {
            LOGGER.severe("Repeated nonce received");
            return State.ERROR;
        }

        int iterationCount = ((iterationBytes[0] & 0xFF) << 8) | (iterationBytes[1] & 0xFF);
        // Nonce 3 incremented for the next message
        byte[] incrementedServerNonce = Utils.getIncrementedBytes(serverNonce);

        // Nonce 4 and UDP port that will be used for the next message
        byte[] clientNonce = clientCryptoSpec.generateShpNonce();

        byte[] data = Utils.concat(request.getBytes(), this.userId.getBytes(), incrementedServerNonce, clientNonce, udpPortBytes);

        try {
            byte[] passwordEncryptedData = clientCryptoSpec.passwordBasedEncrypt(data, new String(passwordDigest), salt, iterationCount);
            byte[] ydhClient = clientCryptoSpec.getYdhBytes();
            byte[] digitalSig = clientCryptoSpec.sign(Utils.concat(data, ydhClient));

            byte[] integrityProof = clientCryptoSpec.createIntegrityProof(Utils.concat(passwordEncryptedData, ydhClient, digitalSig));
            output.writeObject(createShpMessage(header, passwordEncryptedData, ydhClient, digitalSig, integrityProof));

            return State.ONGOING;

        } catch (IOException | GeneralSecurityException e) {
            LOGGER.severe("Error sending message type 3");
            return State.ERROR;
        }
    }

    private State handleType4Message(List<byte[]> payload) {
        LOGGER.info("Received message type 4");

        byte[] publicKeyEncryptedData = payload.get(0);
        byte[] ydhServer = payload.get(1);
        byte[] serverSignature = payload.get(2);
        byte[] integrityProofReceived = payload.get(3);

        // The data to be verified is the message part without the hmac
        byte[] dataToVerify = Utils.concat(publicKeyEncryptedData, ydhServer, serverSignature);

        try {
            if (!clientCryptoSpec.verifyIntegrity(dataToVerify, integrityProofReceived)) {
                LOGGER.severe("Message has been tampered with");
                return State.ERROR;
            }

            byte[] decryptedData = clientCryptoSpec.asymmetricDecrypt(publicKeyEncryptedData);

            // These offsets delimit where each component of the data starts
            // The first component (which has offset 0) is the response
            int firstNonceOffset = ShpCryptoSpec.REQUEST_CONFIRMATION.getBytes().length;
            int secondNonceOffset = firstNonceOffset + ShpCryptoSpec.NONCE_SIZE;
            int cryptoConfigOffset = secondNonceOffset + ShpCryptoSpec.NONCE_SIZE;

            byte[][] decryptedDataParts = Utils.divideInParts(decryptedData,
                    firstNonceOffset,
                    secondNonceOffset,
                    cryptoConfigOffset
                    );

            byte[] response = decryptedDataParts[0];

            if (!(new String (response)).equals(ShpCryptoSpec.REQUEST_CONFIRMATION)) {
                LOGGER.severe("Server denied request");
                return State.ERROR;
            }

            byte[] firstNonce = decryptedDataParts[1];
            byte[] secondNonce = decryptedDataParts[2];

            if (!(noncesReceived.add(firstNonce) && noncesReceived.add(secondNonce))) {
                LOGGER.severe("Invalid nonces received");
                return State.ERROR;
            }

            byte[] cryptoConfigBytes = decryptedDataParts[3];

            byte[] signatureMessage = Utils.concat(
                    response,
                    this.userId.getBytes(),
                    firstNonce,
                    secondNonce,
                    cryptoConfigBytes,
                    ydhServer);

            if (!clientCryptoSpec.verifySignature(serverPublicKey, signatureMessage, serverSignature)) {
                LOGGER.severe("Invalid digital signature");
                return State.ERROR;
            }


            byte[] go = ShpCryptoSpec.FINISH_PROTOCOL.getBytes();
            byte[] incrementNonce = Utils.getIncrementedBytes(secondNonce);
            byte[] message = Utils.concat(go, incrementNonce);

            byte[] sharedSecret = clientCryptoSpec.generateSharedSecret(ydhServer);
            byte[] encryptedMessage = clientCryptoSpec.sharedKeyEncrypt(message, HashUtils.SHA3_256.digest(sharedSecret));

            byte[] integrityProof = clientCryptoSpec.createIntegrityProof(encryptedMessage);

            byte[] header = getMessageHeader(MsgType.TYPE_5);

            // Assign output values
            this.cryptoConfig = new String(cryptoConfigBytes, StandardCharsets.UTF_8);
            this.sharedSecret = sharedSecret;

            output.writeObject(createShpMessage(header, encryptedMessage, integrityProof));

            return State.FINISHED;
        } catch (IOException | GeneralSecurityException e) {
            LOGGER.severe("Error sending message type 5: " + e.getMessage());
            return State.ERROR;
        }
    }

    @Override
    protected boolean isConnectionClosed() {
        return socket.isClosed();
    }

    protected void loadClientResources() {
        try {
            this.serverPublicKey = ShpCryptoSpec.loadPublicKeyFromFile(SERVER_ECC_PUBLIC_KEY_PATH);
            this.clientCryptoSpec = new ShpCryptoSpec(CLIENT_ECC_KEYPAIR_PATH);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to load client resources.", e);
        }
    }
}
