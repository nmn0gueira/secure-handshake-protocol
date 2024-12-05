package pt.unl.fct.shp;

import pt.unl.fct.common.Utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Abstract class for SHP peers (client and server).
 * It contains common methods for handling SHP messages which slightly differ between client and server.
 */
public abstract class AbstractShpPeer {

    protected enum MsgType {
        TYPE_0, // Unused
        TYPE_1,
        TYPE_2,
        TYPE_3,
        TYPE_4,
        TYPE_5;
    }

    protected enum State {
        CLOSED,
        ONGOING,
        WAITING,
        FINISHED;
    }

    protected OutputStream output;
    protected InputStream input;
    protected static final int PORT = 7777;
    protected static final byte[] UDP_PORT_BYTES = ByteBuffer.allocate(Integer.BYTES).putInt(PORT).array();
    protected static final int TIMEOUT_MS = 10000;
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    protected final Logger LOGGER = Logger.getLogger(this.getClass().getName());

    // Common header setup for SHP messages
    private static final byte[] SHP_HEADER = new byte[]{
            (byte) (SHP_VERSION << 4 | SHP_RELEASE), // Version and release
            0x00,   // MsgType Code (where it would be)
    };

    protected AbstractShpPeer() {
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
    private byte[][] extractHeaderAndPayload(byte[] message) {
        if (message.length < 2) {   // Should not happen
            LOGGER.severe("Message is too short to contain a header");
            throw new IllegalArgumentException();
        }
        byte[] header = Utils.subArray(message, 0, 2);
        byte[] payload = Utils.subArray(message, 2, message.length);
        return new byte[][]{header, payload};
    }

    // Method to handle reading and processing messages
    private State processMessage() throws IOException {
        byte[] response = new byte[4096];

        int bytesRead = input.read(response, 0, input.available());

        if (bytesRead == -1) {
            LOGGER.warning("Connection closed.");
            return State.CLOSED;
        }
        if (bytesRead == 0) {
            return State.WAITING;  // Connection alive, continue listening for messages
        }

        byte[] actualData = Utils.subArray(response, 0, bytesRead);
        byte[][] message = extractHeaderAndPayload(actualData);
        MsgType msgType = getMessageType(message[0]);

        return handleMessage(msgType, message[1]);
    }

    protected MsgType getMessageType(byte[] header) {
        return MsgType.values()[header[1]];
    }


    protected abstract State handleMessage(MsgType msgType, byte[] bytes);


    protected void runProtocol() {
        long timeout = System.currentTimeMillis() + TIMEOUT_MS;

        // Main loop for processing messages
        while (!isConnectionClosed() && System.currentTimeMillis() < timeout) {
            try {
                switch (processMessage()) {
                    case CLOSED -> {
                        LOGGER.warning("Connection closed.");
                        return;
                    }
                    case FINISHED -> {
                        LOGGER.info("Protocol finished.");
                        return;
                    }
                    case ONGOING -> timeout = System.currentTimeMillis() + TIMEOUT_MS;
                    case WAITING -> Thread.sleep(1000);
                }
            } catch (InterruptedException e) {
                LOGGER.warning("Protocol interrupted.");
                Thread.currentThread().interrupt();
                break;
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error during protocol execution.", e);
                throw new RuntimeException(e);
            }
        }
    }

    // Check if the socket is closed (client or server)
    protected abstract boolean isConnectionClosed();

    protected abstract void loadResources();
}
