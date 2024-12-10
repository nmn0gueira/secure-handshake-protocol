package pt.unl.fct.shp.server;

import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.CryptoUtils;
import pt.unl.fct.shp.AbstractShpPeer;
import pt.unl.fct.shp.crypto.ShpCryptoSpec;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

public class ShpServer extends AbstractShpPeer {

    private static final String SERVER_ECC_KEYPAIR_PATH = "server/ServerECCKeyPair.sec";
    private final Map<String, User> userDatabase;
    private final Set<String> validRequests;
    private final ShpCryptoSpec serverCryptoSpec;
    private final ServerSocket serverSocket;
    private Socket clientSocket;


    /**
     * Creates a new SHP server.
     *
     * @throws IOException - if an I/O error occurs when creating the ServerSocket.
     */
    public ShpServer(Set<String> validRequests) throws IOException {
        userDatabase = new HashMap<>();
        this.validRequests = validRequests;
        this.serverSocket = new ServerSocket(PORT);
        this.serverCryptoSpec = new ShpCryptoSpec(SERVER_ECC_KEYPAIR_PATH);
        LOGGER.info("Server is listening on port " + PORT);
        loadResources();
        runProtocol();
    }

    @Override
    protected void loadResources() {
        try {
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
            userDatabase.put(userId, new User(userId, passwordHash, salt, CryptoUtils.loadECPublicKey(publicKeyBytes)));
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
        User user = userDatabase.get(userId);
        if (user == null) {
            LOGGER.warning("User not found.");
            return State.ERROR;
        }

        serverCryptoSpec.initIntegrityCheck(user.passwordHash());

        byte[] salt = ShpCryptoSpec.generateShpNonce();
        byte[] iterationBytes = ShpCryptoSpec.generateShpIterationBytes();
        byte[] nonce = ShpCryptoSpec.generateShpNonce();

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
        try {

            /*
            int encryptedDataLength = bytes.length
                    - serverCryptoSpec.getPublicDiffieHellmanKeyLength()
                    - serverCryptoSpec.getDigitalSignatureLength()
                    - serverCryptoSpec.getIntegrityProofSize();

            byte[][] messageParts = Utils.divideInParts(payload,
                    0,
                    encryptedDataLength,
                    encryptedDataLength + serverCryptoSpec.getPublicDiffieHellmanKeyLength(),
                    encryptedDataLength + serverCryptoSpec.getPublicDiffieHellmanKeyLength() + serverCryptoSpec.getDigitalSignatureLength(),
                    payload.length - serverCryptoSpec.getIntegrityProofSize(),
                    payload.length);

            byte[] encryptedData = messageParts[0];
            byte[] clientPublicKeyBytes = messageParts[1];
            byte[] clientSignature = messageParts[2];
            byte[] hmac = messageParts[3];


            byte[] dataToVerifyHmac = Utils.subArray(payload, 0, payload.length - serverCryptoSpec.getIntegrityProofSize());
            if (!serverCryptoSpec.verifyIntegrity(dataToVerifyHmac, hmac)) {
                LOGGER.severe("Failed HMAC verification.");
                return;
            }


            PublicKey clientPublicKey = CryptoUtils.loadECPublicKey(clientPublicKeyBytes);
            byte[] signatureData = Utils.concat(encryptedData, clientPublicKeyBytes);
            if (!serverCryptoSpec.verify(clientPublicKey, signatureData, clientSignature)) {
                LOGGER.severe("Invalid client digital signature.");
                return;
            }


            byte[] decryptedData = serverCryptoSpec.passwordBasedDecrypt(encryptedData);

            byte[] header = getMessageHeader(MsgType.TYPE_4);
            */

            System.out.println("Chegou aqui");
            return State.ONGOING;

        } catch (Exception e) { // TODO: Specialize this exception
            LOGGER.log(Level.SEVERE, "Error processing TYPE_3 message.", e);
            return State.ERROR;
        }
    }

    private State handleType5Message(List<byte[]> payload){
        LOGGER.info("Received message type 5.");
        try {

            return State.FINISHED;

        } catch (Exception e) { // TODO: Specialize this exception
            LOGGER.log(Level.SEVERE, "Error processing TYPE_5 message.", e);
            return State.ERROR;
        }
    }

}
