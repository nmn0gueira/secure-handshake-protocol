package pt.unl.fct.shp;

import pt.unl.fct.common.Utils;

import java.io.InputStream;
import java.io.OutputStream;

public abstract class AbstractSHPPeer {

    protected enum MsgType {
        TYPE_0, // Unused
        TYPE_1,
        TYPE_2,
        TYPE_3,
        TYPE_4,
        TYPE_5;
    }

    protected OutputStream output;
    protected InputStream input;
    protected static final int PORT = 7777;
    protected static final int TIMEOUT_MS = 10000;
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    // Common header setup for SHP messages
    private static final byte[] SHP_HEADER = new byte[]{
            (byte) (SHP_VERSION << 4 | SHP_RELEASE), // Version and release
            0x00,   // MsgType Code (where it would be)
    };

    protected AbstractSHPPeer() {

    }

    /**
     * Creates an SHP message header from the provided message type.
     * @param type - message type
     * @return - SHP message header
     */
    protected byte[] getMessageHeader(MsgType type) {
        return new byte[]{SHP_HEADER[0], (byte) type.ordinal()};
    }

    /**
     * Extract header and payload from the provided message.
     */
    protected byte[][] extractHeaderAndPayload(byte[] message) {
        if (message.length < 2) {   // Should not happen
            throw new IllegalArgumentException("Message is too short to contain a header");
        }
        byte[] header = Utils.subArray(message, 0, 2);
        byte[] payload = Utils.subArray(message, 2, message.length);
        return new byte[][]{header, payload};
    }

    // Refactored method to handle reading and processing messages
    protected boolean processMessage() throws IOException {
        byte[] response = new byte[1024];
        int bytesRead = input.read(response);

        if (bytesRead == -1) {
            LOGGER.info("Connection closed.");
            return false;
        }
        if (bytesRead == 0) {
            return true;  // Connection alive, continue listening for messages
        }

        byte[] actualData = Utils.subArray(response, 0, bytesRead);
        byte[][] message = extractHeaderAndPayload(actualData);
        MsgType msgType = getMessageType(message[0]);

        handleMessage(msgType, message[1]);

        return msgType != MsgType.TYPE_5; // If TYPE_5 is received, server finishes
    }

    protected MsgType getMessageType(byte[] header) {
        return MsgType.values()[header[1]];
    }


    protected abstract void handleMessage(MsgType msgType, byte[] bytes);

    protected abstract void runProtocol();

    protected abstract void loadResources();
}
