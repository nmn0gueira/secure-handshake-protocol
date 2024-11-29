package pt.unl.fct.common;

/**
 * Material/Labs para SRSC 20/21, Sem-1
 * hj
 **/

/**
 * Auxiliar
 * Some conversion functions
 */
public class CommonUtils
{
    private static final String digits = "0123456789abcdef";

    /**
     * Return string hexadecimal from byte array of certain size
     *
     * @param data : bytes to convert
     * @param length : nr of bytes in data block to be converted
     * @return  hex : hexadecimal representation of data
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuilder buf = new StringBuilder();

        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return data in byte array from string hexadecimal
     *
     * @param data : bytes to be converted
     * @return : hexadecimal representation of data
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

    /**
     *
     * @param array
     * @param start - the start index of the substring (inclusive)
     * @param end - the end index of the substring (exclusive)
     * @return
     */
    public static byte[] subArray(byte[] array, int start, int end) {
        byte[] result = new byte[end - start];
        System.arraycopy(array, start, result, 0, result.length);
        return result;
    }

    /**
     * Returns the hexadecimal representation of the payload, with the header and data divided by a separator.
     * For visual purposes.
     * @param payload - the payload to be represented
     * @return - the hexadecimal representation of the payload
     */
    public static String getPayloadRepresentation(byte[] payload) {
        byte[] header = new byte[5];
        System.arraycopy(payload, 0, header, 0, 5);
        byte[] data = new byte[payload.length - 5];
        System.arraycopy(payload, 5, data, 0, data.length);
        return getHexRepresentation(header) + " || " + getHexRepresentation(data);
    }

    /**
     * Returns the hexadecimal representation of the data, with every byte being separated by a space.
     * For visual purposes.
     * @param data - the data to be represented
     * @return - the hexadecimal representation of the data
     */
    public static String getHexRepresentation(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(CommonUtils.toHex(new byte[]{data[i]}));
            if (i != data.length - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    /**
     * Transform a number of x bytes into y bytes (ex: 2 bytes into 4 bytes or 4 bytes into 2 bytes)
     * @param data
     * @param x
     * @return
     */
    public static byte[] toXBytes(byte[] data, int x) {
        if (x > data.length) {
            byte[] result = new byte[x];
            System.arraycopy(data, 0, result, x - data.length, data.length);
            return result;
        }
        else if (data.length == x) {
            return data;
        }
        else {
            return subArray(data, data.length - x, data.length);
        }
    }
}



