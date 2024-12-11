package pt.unl.fct.shp;

import pt.unl.fct.common.Utils;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ShpMessage implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final byte[] header;
    private final List<byte[]> payload;

    /**
     * This class is used to encapsulate the three components of a message in the SHP protocol, saving three buffers
     */
    public ShpMessage(byte[] header, byte[]... components)  {
        this.header = header;
        this.payload = new ArrayList<>();
        this.payload.addAll(Arrays.asList(components));
    }

    public byte[] getHeader() {
        return header;
    }

    public List<byte[]> getPayload() {
        return payload;
    }

    @Override
    public String toString() {
        // Print the header and each separate component in hexadecimal format
        StringBuilder sb = new StringBuilder();
        sb.append("Header: ").append(Utils.byteArrayToHexString(header)).append("\n");
        for (int i = 0; i < payload.size(); i++) {
            sb.append("Payload component ").append(i).append(": ").append(Utils.byteArrayToHexString(payload.get(i))).append("\n");
        }
        return sb.toString();
    }
}

