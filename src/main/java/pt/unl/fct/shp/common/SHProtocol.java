package pt.unl.fct.shp.common;

import pt.unl.fct.common.CommonUtils;

public class SHProtocol {

    public enum MsgType {
        TYPE_0, // Unused
        TYPE_1,
        TYPE_2,
        TYPE_3,
        TYPE_4,
        TYPE_5;
    }

    public static final int TIMEOUT_MS = 10000;
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    // Common header setup for SHP messages
    private static final byte[] SHP_HEADER = new byte[]{
            (byte) (SHP_VERSION << 4 | SHP_RELEASE), // Version and release
            0x00,   // MsgType Code (where it would be)
    };

    /**
     * Creates an SHP message header from the provided message type.
     * @param type - message type
     * @return - SHP message header
     */
    public static byte[] getMessageHeader(MsgType type) {
        return new byte[]{SHP_HEADER[0], (byte) type.ordinal()};
    }

    /**
     * Extract header and payload from the provided message.
     */
    public static byte[][] extractHeaderAndPayload(byte[] message) {
        if (message.length < 2) {   // Should not happen
            throw new IllegalArgumentException("Message is too short to contain a header");
        }
        byte[] header = CommonUtils.subArray(message, 0, 2);
        byte[] payload = CommonUtils.subArray(message, 2, message.length);
        return new byte[][]{header, payload};
    }

    public static MsgType getMessageType(byte[] header) {
        return MsgType.values()[header[1]];
    }
}
