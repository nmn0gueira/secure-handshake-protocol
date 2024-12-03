package pt.unl.fct.shp.client;

import pt.unl.fct.common.Utils;
import pt.unl.fct.shp.ShpCryptoSpec;
import pt.unl.fct.shp.AbstractShpPeer;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.HashSet;
import java.util.logging.Level;


public class ShpClient extends AbstractShpPeer {

    private final Socket socket;
    private final String request;
    private static final String USER_ID = "userId";
    private static final String PASSWORD = "password";
    private KeyPair digitalSignatureKeyPair;
    private KeyPair keyAgreementKeyPair;
    private PublicKey serverPublicKey;
    private KeyAgreement keyAgreement;
    private static final byte[] hmacKey = ShpCryptoSpec.generateHash(PASSWORD.getBytes()); //TODO: Refactor this
    private static final byte[] UDP_PORT_BYTES = ByteBuffer.allocate(Integer.BYTES).putInt(PORT).array();
    private final HashSet<byte[]> noncesReceived;


    public ShpClient(String request) throws IOException, InvalidKeyException {
        this.socket = new Socket("localhost", PORT);
        this.request = request;
        this.output = socket.getOutputStream();
        this.input = socket.getInputStream();
        this.noncesReceived = new HashSet<>();
        loadResources();
        keyAgreement.init(keyAgreementKeyPair.getPrivate());
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

        // Nonce 1 and 2 that will be used for PBE and nonce 3 that will be used for the next message nonce
        byte[] salt = Utils.subArray(bytes, 0, ShpCryptoSpec.SALT_SIZE);
        byte[] iterationBytes = Utils.subArray(bytes, ShpCryptoSpec.SALT_SIZE, ShpCryptoSpec.ITERATION_COUNTER_SIZE);
        byte[] serverNonce = Utils.subArray(bytes, ShpCryptoSpec.SALT_SIZE + ShpCryptoSpec.ITERATION_COUNTER_SIZE, ShpCryptoSpec.NONCE_SIZE);

        // Check if any of the nonces received is repeated TODO: See if it is needed according to protocol specification (slides)
        if (!(noncesReceived.add(salt) && noncesReceived.add(iterationBytes) && noncesReceived.add(serverNonce))) {
            LOGGER.severe("Repeated nonce received");
            throw new RuntimeException("Repeated nonce received");
        }

        int iterationCount = ByteBuffer.wrap(iterationBytes).getInt();

        // Nonce 3 incremented for the next message
        byte[] incrementedServerNonce = ShpCryptoSpec.getIncrementedNonce(serverNonce);

        // Nonce 4 and UDP port that will be used for the next message
        byte[] clientNonce = new byte[ShpCryptoSpec.NONCE_SIZE];
        ShpCryptoSpec.SECURE_RANDOM.nextBytes(clientNonce);

        byte[] data = Utils.concat(request.getBytes(), USER_ID.getBytes(), incrementedServerNonce, clientNonce, UDP_PORT_BYTES);

        try {
            byte[] encryptedData = ShpCryptoSpec.passwordBasedEncryption(data, PASSWORD, salt, iterationCount);
            byte[] ydhClient = keyAgreementKeyPair.getPublic().getEncoded();
            byte[] digitalSig = ShpCryptoSpec.sign(digitalSignatureKeyPair.getPrivate(), Utils.concat(data, ydhClient));

            byte[] message = Utils.concat(header, encryptedData, ydhClient, digitalSig);
            byte[] hmac = ShpCryptoSpec.generateHmac(hmacKey, message);

            output.write(Utils.concat(message, hmac));

        } catch (IOException | GeneralSecurityException e) {
            LOGGER.severe("Error sending message type 3");
            throw new RuntimeException(e);
        }
    }

    private void handleType4Message(byte[] bytes) {
        LOGGER.info("Received message type 4");

        int pubKeyEncryptedDataLength = bytes.length - ShpCryptoSpec.getPublicDiffieHellmanKeyLength() -
                ShpCryptoSpec.getDigitalSignatureLength() - ShpCryptoSpec.getHmacLength();

        byte[][] messageParts = Utils.divideInParts(bytes,
                0,
                pubKeyEncryptedDataLength,
                pubKeyEncryptedDataLength + ShpCryptoSpec.getPublicDiffieHellmanKeyLength(),
                pubKeyEncryptedDataLength + ShpCryptoSpec.getPublicDiffieHellmanKeyLength() + ShpCryptoSpec.getDigitalSignatureLength(),
                bytes.length - ShpCryptoSpec.getHmacLength(),
                bytes.length);

        byte[] publicKeyEncryptedData = messageParts[0];

        byte[] publicServerDiffieHellmanNumber = messageParts[1];

        byte[] digitalSignature = messageParts[2];

        byte[] hmac = messageParts[3];

        // The data to be verified is the message part without the hmac
        byte[] hmacData = Utils.subArray(bytes, 0, bytes.length - ShpCryptoSpec.getHmacLength());

        try {
            if (!ShpCryptoSpec.verifyIntegrity(hmacData, hmacKey, hmac)) {
                LOGGER.severe("Failed integrity proof");
                return;
            }

            byte[] decryptedData = ShpCryptoSpec.decryptECC(publicKeyEncryptedData, digitalSignatureKeyPair.getPrivate());

            byte[][] decryptedDataParts = Utils.divideInParts(decryptedData,
                    0,
                    2,
                    2 + ShpCryptoSpec.NONCE_SIZE,
                    2 + 2 * ShpCryptoSpec.NONCE_SIZE,
                    decryptedData.length);

            byte[] response = decryptedDataParts[0]; // TODO: Make it so the first 2 bytes are the response

            if (!(new String (response)).equals("OK")) {
                LOGGER.severe("Server denied request");
                return;
            }

            byte[] firstNonce = decryptedDataParts[1];
            byte[] secondNonce = decryptedDataParts[2];

            if (!(noncesReceived.add(firstNonce) && noncesReceived.add(secondNonce))) {
                LOGGER.severe("Invalid nonces received");
                return;
            }

            byte[] ciphersuiteBytes = decryptedDataParts[3];

            byte[] signatureMessage = Utils.concat(
                    response,
                    USER_ID.getBytes(),
                    firstNonce,
                    secondNonce,
                    ciphersuiteBytes,
                    publicServerDiffieHellmanNumber);

            if (!ShpCryptoSpec.verify(serverPublicKey, signatureMessage, digitalSignature)) {
                LOGGER.severe("Invalid digital signature");
                return;
            }

            keyAgreement.doPhase(ShpCryptoSpec.loadDHPublicKey(publicServerDiffieHellmanNumber), true);

            byte[] go = "GO".getBytes();
            byte[] incrementNonce = ShpCryptoSpec.getIncrementedNonce(secondNonce);
            byte[] message = Utils.concat(go, incrementNonce);
            byte[] encryptedMessage = ShpCryptoSpec.symmetricEncrypt(message, keyAgreement.generateSecret());
            byte[] messageHmac = ShpCryptoSpec.generateHmac(hmacKey, encryptedMessage);

            output.write(Utils.concat(encryptedMessage, messageHmac));

            //byte[] ciphersuite = Utils.toString(ciphersuiteBytes, ciphersuiteBytes.length);
            //TODO: Create ciphersuite from bytes

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
            digitalSignatureKeyPair = ShpCryptoSpec.loadKeyPairFromFile("client/ClientECCKeyPair.sec");
            serverPublicKey = ShpCryptoSpec.loadPublicKeyFromFile("client/ServerECCPublicKey.txt");
            keyAgreementKeyPair = ShpCryptoSpec.generateKeyAgreementKeyPair();
            keyAgreement = ShpCryptoSpec.createKeyAgreement();
        } catch (IOException | GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Failed to load client resources.", e);
        }

    }
}
