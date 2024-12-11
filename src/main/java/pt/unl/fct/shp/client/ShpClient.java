package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.crypto.ShpCryptoSpec;
import pt.unl.fct.shp.AbstractShpPeer;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.List;
import java.util.logging.Level;


public class ShpClient extends AbstractShpPeer {

    private static final String CLIENT_ECC_KEYPAIR_PATH = "client/ClientECCKeyPair.sec";
    private static final String SERVER_ECC_PUBLIC_KEY_PATH = "client/ServerECCPubKey.txt";
    private static final String USER_ID = "userId";
    private static final String PASSWORD = "password";
    private final Socket socket;
    private final String request;

    private final ShpCryptoSpec clientCryptoSpec;
    private final byte[] udpPortBytes;
    private PublicKey serverPublicKey;
    private final byte[] passwordDigest = ShpCryptoSpec.digest(PASSWORD.getBytes());
    private String cryptoConfig;


    public ShpClient(String userId, String password, String request, int udpPort) throws IOException {
        this.socket = new Socket("localhost", TCP_PORT);
        this.request = request;
        this.output = new ObjectOutputStream(socket.getOutputStream());
        this.input = new ObjectInputStream(socket.getInputStream());
        this.udpPortBytes = ByteBuffer.allocate(Integer.BYTES).putInt(udpPort).array();
        this.clientCryptoSpec = new ShpCryptoSpec(CLIENT_ECC_KEYPAIR_PATH);
        this.clientCryptoSpec.initIntegrityCheck(passwordDigest);
        loadResources();

    }

    public ClientOutput startClient() {
        State state = runProtocol();
        if (state == State.FINISHED) {
            return new ClientOutput(cryptoConfig);
        }
        throw new IllegalStateException("Client did not finish successfully");
    }

    private void init() {
        byte[] header = getMessageHeader(MsgType.TYPE_1);
        byte[] userId = USER_ID.getBytes();
        try {
            output.writeObject(createShpMessage(header, userId));
        } catch (IOException e) {
            LOGGER.severe("Error sending message type 1");
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

    @Override
    protected boolean isConnectionClosed() {
        return socket.isClosed();
    }

    private State handleType2Message(List<byte[]> payload) {
        LOGGER.info("Received message type 2");

        byte[] header = getMessageHeader(MsgType.TYPE_3);

        // Nonce 1 and 2 that will be used for PBE and nonce 3 that will be used for the next message nonce
        byte[] salt = Utils.getFirstBytes(payload.get(0), ShpCryptoSpec.SALT_SIZE);
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
        byte[] clientNonce = ShpCryptoSpec.generateShpNonce();

        byte[] data = Utils.concat(request.getBytes(), USER_ID.getBytes(), incrementedServerNonce, clientNonce, udpPortBytes);

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

            //cryptoConfigBytes = decryptedDataParts[3]; TODO: Create ciphersuite from bytes

            byte[] signatureMessage = Utils.concat(
                    response,
                    USER_ID.getBytes(),
                    firstNonce,
                    secondNonce,
                    //cryptoConfigBytes,
                    ydhServer);

            if (!clientCryptoSpec.verifySignature(serverPublicKey, signatureMessage, serverSignature)) {
                LOGGER.severe("Invalid digital signature");
                return State.ERROR;
            }


            byte[] go = ShpCryptoSpec.FINISH_PROTOCOL.getBytes();
            byte[] incrementNonce = Utils.getIncrementedBytes(secondNonce);
            byte[] message = Utils.concat(go, incrementNonce);

            byte[] sharedKey = clientCryptoSpec.generateSharedKey(ydhServer);
            byte[] encryptedMessage = clientCryptoSpec.sharedKeyEncrypt(message, sharedKey);

            byte[] integrityProof = clientCryptoSpec.createIntegrityProof(encryptedMessage);

            byte[] header = getMessageHeader(MsgType.TYPE_5);
            output.writeObject(createShpMessage(header, encryptedMessage, integrityProof));


            //TODO: Create ciphersuite from bytes

            socket.close();

            return State.FINISHED;
        } catch (IOException | GeneralSecurityException e) {
            LOGGER.severe("Error sending message type 5: " + e.getMessage());
            return State.ERROR;
        }
    }

    protected State runProtocol() {
        init();
        return super.runProtocol();
    }


    @Override
    protected void loadResources() {
        try {
            serverPublicKey = ShpCryptoSpec.loadPublicKeyFromFile(SERVER_ECC_PUBLIC_KEY_PATH);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to load client resources.", e);
        }

    }
}
