package pt.unl.fct.shp;

import java.io.*;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
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
        TYPE_5
    }

    protected enum State {
        ONGOING,
        WAITING,
        ERROR,
        FINISHED
    }

    protected static final int TIMEOUT_MS = 10000;
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    protected ObjectOutputStream output;
    protected ObjectInputStream input;
    protected final HashSet<byte[]> noncesReceived;
    private final BlockingQueue<Object> objectQueue;

    protected final Logger LOGGER = Logger.getLogger(this.getClass().getName());

    // Common header setup for SHP messages
    private static final byte[] SHP_HEADER = new byte[]{
            (byte) (SHP_VERSION << 4 | SHP_RELEASE), // Version and release
            0x00,   // MsgType Code (where it would be)
    };

    protected AbstractShpPeer() {
        noncesReceived = new HashSet<>();
        objectQueue = new LinkedBlockingQueue<>();
        LOGGER.setLevel(Level.OFF);
    }

    /**
     * Creates an SHP message header from the provided message type.
     * @param type - message type
     * @return - SHP message header
     */
    protected byte[] getMessageHeader(MsgType type) {
        return new byte[]{SHP_HEADER[0], (byte) type.ordinal()};
    }

    // Method to handle reading and processing messages
    private State processMessage() throws IOException {
        try {
            Object receivedObject = objectQueue.poll(); // Non-blocking, returns null if empty

            if (receivedObject == null) {
                return State.WAITING; // No object available, wait for next call
            }

            if (receivedObject instanceof ShpMessage message) {
                MsgType msgType = getMessageType(message.getHeader());
                return handleMessage(msgType, message.getPayload());
            } else {
                LOGGER.warning("Unexpected object type: " + receivedObject.getClass());
                return State.ERROR;
            }
        } catch (Exception e) {
            LOGGER.severe("Error processing message: " + e.getMessage());
            return State.ERROR;
        }

    }

    protected MsgType getMessageType(byte[] header) {
        return MsgType.values()[header[1]];
    }

    protected abstract State handleMessage(MsgType msgType, List<byte[]> payload);

    @SuppressWarnings("all")
    protected State runProtocol() {
        startObjectReader(input);

        long timeout = System.currentTimeMillis() + TIMEOUT_MS;
        boolean timeoutCondition = false;

        // Main loop for processing messages
        while (!isConnectionClosed() && (timeoutCondition = System.currentTimeMillis() < timeout)) {
            try {
                switch (processMessage()) {
                    case ERROR -> {
                        LOGGER.warning("Error during protocol execution.");
                        return State.ERROR;
                    }
                    case FINISHED -> {
                        LOGGER.info("Protocol finished.");
                        return State.FINISHED;
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
        if (!timeoutCondition) {
            LOGGER.warning("Timeout reached.");
            return State.ERROR;
        }

        LOGGER.info("Connection closed.");
        return State.ERROR;
    }

    private void startObjectReader(ObjectInputStream objectInputStream) {
        Thread readerThread = new Thread(() -> {
            try {
                while (true) {
                    Object receivedObject = objectInputStream.readObject();
                    objectQueue.put(receivedObject);
                }
            } catch (EOFException | InterruptedException e) {
                LOGGER.info("End of stream reached, stopping reader thread.");
            } catch (IOException e) {
                LOGGER.severe("Socket closed, stopping reader thread");
            } catch (ClassNotFoundException e) {
                LOGGER.severe("Class not found: " + e.getMessage());
            }
        });
        readerThread.setDaemon(true);
        readerThread.start();
    }


    protected abstract boolean isConnectionClosed();

    protected void closeStreams() throws IOException {
        if (output != null) {
            output.close();
        }
        if (input != null) {
            input.close();
        }
    }

    protected ShpMessage createShpMessage(byte[] header, byte[]... components) {
        return new ShpMessage(header, components);
    }
}
