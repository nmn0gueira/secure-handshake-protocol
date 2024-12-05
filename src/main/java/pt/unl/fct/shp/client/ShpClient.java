package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.CryptoUtils;
import pt.unl.fct.shp.crypto.ShpCryptoSpec;
import pt.unl.fct.shp.AbstractShpPeer;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.HashSet;
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
        this.output = socket.getOutputStream();
        this.input = socket.getInputStream();
        this.noncesReceived = new HashSet<>();
        this.clientCryptoSpec = new ShpCryptoSpec(CLIENT_ECC_KEYPAIR_PATH);
        this.clientCryptoSpec.initIntegrityCheck(ShpCryptoSpec.digest(PASSWORD.getBytes()));
        loadResources();
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
    protected State handleMessage(MsgType msgType, byte[] bytes) {
        switch (msgType) {
            case TYPE_2 ->  {
                handleType2Message(bytes);
                return State.ONGOING;
            }
            case TYPE_4 ->  {
                handleType4Message(bytes);
                return State.FINISHED;
            }
            default -> {
                LOGGER.severe("Unexpected message type: " + msgType);
                throw new IllegalStateException(); // Should not happen
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
        // Nonce 1 and 2 that will be used for PBE and nonce 3 that will be used for the next message nonce
        byte[][] receivedData = Utils.divideInParts(bytes,
                0,
                ShpCryptoSpec.SALT_SIZE,
                ShpCryptoSpec.SALT_SIZE + ShpCryptoSpec.ITERATION_COUNTER_SIZE,
                ShpCryptoSpec.SALT_SIZE + ShpCryptoSpec.ITERATION_COUNTER_SIZE + ShpCryptoSpec.NONCE_SIZE);

        byte[] salt = receivedData[0];
        byte[] iterationBytes = receivedData[1];
        byte[] serverNonce = receivedData[2];

        // Check if any of the nonces received is repeated TODO: See if it is needed according to protocol specification (slides)
        if (!(noncesReceived.add(salt) && noncesReceived.add(iterationBytes) && noncesReceived.add(serverNonce))) {
            LOGGER.severe("Repeated nonce received");
            throw new RuntimeException();
        }

        int iterationCount = ((iterationBytes[0] & 0xFF) << 8) | (iterationBytes[1] & 0xFF);
        // Nonce 3 incremented for the next message
        byte[] incrementedServerNonce = Utils.getIncrementedBytes(serverNonce);

        // Nonce 4 and UDP port that will be used for the next message
        byte[] clientNonce = ShpCryptoSpec.generateShpNonce();

        byte[] data = Utils.concat(request.getBytes(), USER_ID.getBytes(), incrementedServerNonce, clientNonce, UDP_PORT_BYTES);

        try {
            byte[] encryptedData = clientCryptoSpec.passwordBasedEncrypt(data, PASSWORD, salt, iterationCount);
            byte[] ydhClient = clientCryptoSpec.getPublicDiffieHellmanKeyBytes();
            byte[] digitalSig = clientCryptoSpec.sign(Utils.concat(data, ydhClient));

            byte[] message = Utils.concat(encryptedData, ydhClient, digitalSig);
            byte[] hmac = clientCryptoSpec.createIntegrityProof(message);

            output.write(Utils.concat(header, message, hmac));

        } catch (IOException | GeneralSecurityException e) {
            LOGGER.severe("Error sending message type 3");
            throw new RuntimeException(e);
        }
    }

    private void handleType4Message(byte[] bytes) {
        LOGGER.info("Received message type 4");

        int publicKeyEncryptedDataLength = bytes.length - clientCryptoSpec.getPublicDiffieHellmanKeyLength() -
                clientCryptoSpec.getDigitalSignatureLength() - clientCryptoSpec.getIntegrityProofSize();

        byte[][] messageParts = Utils.divideInParts(bytes,
                0,
                publicKeyEncryptedDataLength,
                publicKeyEncryptedDataLength + clientCryptoSpec.getPublicDiffieHellmanKeyLength(),
                publicKeyEncryptedDataLength + clientCryptoSpec.getPublicDiffieHellmanKeyLength() + clientCryptoSpec.getDigitalSignatureLength(),
                bytes.length - clientCryptoSpec.getIntegrityProofSize(),
                bytes.length);

        byte[] publicKeyEncryptedData = messageParts[0];

        byte[] publicServerDiffieHellmanNumber = messageParts[1];

        byte[] digitalSignature = messageParts[2];

        byte[] integrityProof = messageParts[3];

        // The data to be verified is the message part without the hmac
        byte[] dataToVerify = Utils.subArray(bytes, 0, bytes.length - clientCryptoSpec.getIntegrityProofSize());

        try {
            if (!clientCryptoSpec.verifyIntegrity(dataToVerify, integrityProof)) {
                LOGGER.severe("Failed integrity proof");
                return;
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
                return;
            }

            byte[] firstNonce = decryptedDataParts[1];
            byte[] secondNonce = decryptedDataParts[2];

            if (!(noncesReceived.add(firstNonce) && noncesReceived.add(secondNonce))) {
                LOGGER.severe("Invalid nonces received");
                return;
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
                return;
            }

            byte[] sharedKey = clientCryptoSpec.generateSharedKey(publicServerDiffieHellmanNumber);

            byte[] go = ShpCryptoSpec.FINISH_PROTOCOL.getBytes();
            byte[] incrementNonce = Utils.getIncrementedBytes(secondNonce);
            byte[] message = Utils.concat(go, incrementNonce);
            byte[] encryptedMessage = clientCryptoSpec.sharedKeyEncrypt(message, sharedKey);
            byte[] messageHmac = clientCryptoSpec.createIntegrityProof(encryptedMessage);

            output.write(Utils.concat(encryptedMessage, messageHmac));

            //byte[] ciphersuite = Utils.toString(ciphersuiteBytes, ciphersuiteBytes.length);
            //TODO: Create ciphersuite from bytes

            byte[] header = getMessageHeader(MsgType.TYPE_5);

            socket.close();
        } catch (IOException e) {
            LOGGER.severe("Error closing socket");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
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
