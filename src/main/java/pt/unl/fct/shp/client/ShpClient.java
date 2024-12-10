package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.CryptoUtils;
import pt.unl.fct.shp.crypto.ShpCryptoSpec;
import pt.unl.fct.shp.AbstractShpPeer;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;


public class ShpClient extends AbstractShpPeer {

    private static final String CLIENT_ECC_KEYPAIR_PATH = "client/ClientECCKeyPair.sec";
    private static final String SERVER_ECC_PUBLIC_KEY_PATH = "client/ServerECCPubKey.txt";
    private static final String USER_ID = "userId";
    private static final String PASSWORD = "password";
    private final Socket socket;
    private final String request;
    private final HashSet<byte[]> noncesReceived;
    private final ShpCryptoSpec clientCryptoSpec;
    private PublicKey serverPublicKey;


    public ShpClient(String request) throws IOException {
        this.socket = new Socket("localhost", PORT);
        this.request = request;
        this.output = new ObjectOutputStream(socket.getOutputStream());
        this.input = new ObjectInputStream(socket.getInputStream());
        this.noncesReceived = new HashSet<>();
        this.clientCryptoSpec = new ShpCryptoSpec(CLIENT_ECC_KEYPAIR_PATH);
        this.clientCryptoSpec.initIntegrityCheck(ShpCryptoSpec.digest(PASSWORD.getBytes()));
        loadResources();
        runProtocol();
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
        byte[] iterationBytes = Utils.getFirstBytes(payload.get(1), ShpCryptoSpec.ITERATION_COUNTER_SIZE);
        byte[] serverNonce = payload.get(2);

        // Check if any of the nonces received is repeated
        if (!(noncesReceived.add(salt) && noncesReceived.add(iterationBytes) && noncesReceived.add(serverNonce))) {
            LOGGER.severe("Repeated nonce received");
            return State.ERROR;
        }

        int iterationCount = ((iterationBytes[0] & 0xFF) << 8) | (iterationBytes[1] & 0xFF);
        // Nonce 3 incremented for the next message
        byte[] incrementedServerNonce = Utils.getIncrementedBytes(serverNonce);

        // Nonce 4 and UDP port that will be used for the next message
        byte[] clientNonce = ShpCryptoSpec.generateShpNonce();

        byte[] data = Utils.concat(request.getBytes(), USER_ID.getBytes(), incrementedServerNonce, clientNonce, UDP_PORT_BYTES);

        try {
            byte[] passwordEncryptedData = clientCryptoSpec.passwordBasedEncrypt(data, PASSWORD, salt, iterationCount);
            byte[] ydhClient = clientCryptoSpec.getPublicDiffieHellmanKeyBytes();
            byte[] digitalSig = clientCryptoSpec.sign(Utils.concat(data, ydhClient));

            byte[] message = Utils.concat(passwordEncryptedData, ydhClient, digitalSig);
            byte[] hmac = clientCryptoSpec.createIntegrityProof(message);
            output.writeObject(createShpMessage(header, passwordEncryptedData, ydhClient, digitalSig, hmac));

            return State.ONGOING;

        } catch (IOException | GeneralSecurityException e) {
            LOGGER.severe("Error sending message type 3");
            return State.ERROR;
        }
    }

    private State handleType4Message(List<byte[]> payload) {
        LOGGER.info("Received message type 4");

        byte[] publicKeyEncryptedData = payload.get(0);

        byte[] publicServerDiffieHellmanNumber = payload.get(1);

        byte[] digitalSignature = payload.get(2);

        byte[] integrityProof = payload.get(3);

        // The data to be verified is the message part without the hmac
        byte[] dataToVerify = Utils.concat(publicKeyEncryptedData, publicServerDiffieHellmanNumber, digitalSignature);

        try {
            if (!clientCryptoSpec.verifyIntegrity(dataToVerify, integrityProof)) {
                LOGGER.severe("Failed integrity proof");
                return State.ERROR;
            }

            byte[] decryptedData = clientCryptoSpec.asymmetricDecrypt(publicKeyEncryptedData);

            byte[][] decryptedDataParts = Utils.divideInParts(decryptedData,
                    0,
                    2,
                    2 + ShpCryptoSpec.NONCE_SIZE,
                    2 + 2 * ShpCryptoSpec.NONCE_SIZE,
                    decryptedData.length);

            // TODO: Make it so the first 2 bytes are the response (this may be a problem if it is supposed to be a string of variable length)
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

            byte[] cipherSuiteBytes = decryptedDataParts[3];

            byte[] signatureMessage = Utils.concat(
                    response,
                    USER_ID.getBytes(),
                    firstNonce,
                    secondNonce,
                    cipherSuiteBytes,
                    publicServerDiffieHellmanNumber);

            if (!clientCryptoSpec.verify(serverPublicKey, signatureMessage, digitalSignature)) {
                LOGGER.severe("Invalid digital signature");
                return State.ERROR;
            }

            byte[] sharedKey = clientCryptoSpec.generateSharedKey(publicServerDiffieHellmanNumber);

            byte[] go = ShpCryptoSpec.FINISH_PROTOCOL.getBytes();
            byte[] incrementNonce = Utils.getIncrementedBytes(secondNonce);
            byte[] message = Utils.concat(go, incrementNonce);
            byte[] encryptedMessage = clientCryptoSpec.sharedKeyEncrypt(message, sharedKey);
            byte[] messageHmac = clientCryptoSpec.createIntegrityProof(encryptedMessage);

            byte[] header = getMessageHeader(MsgType.TYPE_5);
            output.writeObject(createShpMessage(header, encryptedMessage, messageHmac));

            //byte[] ciphersuite = Utils.toString(ciphersuiteBytes, ciphersuiteBytes.length);
            //TODO: Create ciphersuite from bytes

            socket.close();

            return State.FINISHED;
        } catch (IOException e) {
            LOGGER.severe("Error closing socket");
            return State.ERROR;
        } catch (GeneralSecurityException e) {
            return State.ERROR;
        }
    }

    protected void runProtocol() {
        init();
        super.runProtocol();
    }


    @Override
    protected void loadResources() {
        try {
            serverPublicKey = CryptoUtils.loadPublicKeyFromFile(SERVER_ECC_PUBLIC_KEY_PATH);
        } catch (IOException | GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Failed to load client resources.", e);
        }

    }
}
