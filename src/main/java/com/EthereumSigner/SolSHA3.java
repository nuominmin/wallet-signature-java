package com.example;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SolSHA3 {
    public static byte[] SoliditySHA3(List<String> types, List<Object> values) {
        if (types.size() != values.size()) {
            throw new IllegalArgumentException("Types and values array must have the same length");
        }
        List<byte[]> packedData = new ArrayList<>();
        for (int i = 0; i < types.size(); i++) {
            packedData.add(pack(types.get(i), values.get(i), false));
        }
        byte[] concatenated = concatenate(packedData);
        Keccak.Digest256 keccak256 = new Keccak.Digest256();
        keccak256.update(concatenated, 0, concatenated.length);
        return keccak256.digest();
    }

    private static byte[] pack(String type, Object value, boolean isArray) {
        if (type.equals("address")) {
            byte[] addr = packAddress((String) value);
            return isArray ? leftPad(addr, 32) : addr;
        } else if (type.equals("string")) {
            return packString((String) value);
        } else if (type.equals("bool")) {
            byte[] bool = packBool((Boolean) value);
            return isArray ? leftPad(bool, 32) : bool;
        } else if (type.matches("^bytes[0-9]+$")) {
            return packBytesN(type, value, isArray);
        } else if (type.matches("^bytes$")) {
            return (byte[]) value;
        } else if (type.matches("^u?int[0-9]*$")) {
            byte[] integer = packInteger(type, value);
            return isArray ? leftPad(integer, 32) : integer;
        } else if (type.matches("^(.*)\\[\\d*\\]$")) {
            return packArray(type, value);
        } else {
            throw new IllegalArgumentException("Unsupported type: " + type);
        }
    }

    private static byte[] packAddress(String value) {
        String address = value.startsWith("0x") ? value.substring(2) : value;
        if (address.length() != 40) {
            throw new IllegalArgumentException("Invalid address: " + value);
        }
        return hexStringToByteArray(address);
    }

    private static byte[] packString(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] packBool(Boolean value) {
        byte[] bytes = new byte[1];
        bytes[0] = value ? (byte) 1 : (byte) 0;
        return bytes;
    }

    private static byte[] packBytesN(String type, Object value, boolean isArray) {
        int n = Integer.parseInt(type.substring(5));
        if (n < 1 || n > 32) {
            throw new IllegalArgumentException("Invalid bytesN length: " + n);
        }
        byte[] bytes;
        if (value instanceof String) {
            String hex = (String) value;
            if (hex.startsWith("0x")) {
                hex = hex.substring(2);
            }
            bytes = hexStringToByteArray(hex);
        } else if (value instanceof byte[]) {
            bytes = (byte[]) value;
        } else {
            throw new IllegalArgumentException("Invalid value for type " + type);
        }
        if (bytes.length != n) {
            throw new IllegalArgumentException("Invalid value length for type " + type);
        }
        return isArray ? rightPad(bytes, 32) : bytes;
    }

    private static byte[] packInteger(String type, Object value) {
        boolean unsigned = type.startsWith("uint");
        int bits = 256;
        if (type.length() > (unsigned ? 4 : 3)) {
            bits = Integer.parseInt(type.substring(unsigned ? 4 : 3));
        }
        if (bits % 8 != 0 || bits == 0 || bits > 256) {
            throw new IllegalArgumentException("Invalid integer type: " + type);
        }
        BigInteger bigIntValue;
        if (value instanceof String) {
            bigIntValue = new BigInteger((String) value);
        } else if (value instanceof Number) {
            bigIntValue = BigInteger.valueOf(((Number) value).longValue());
        } else if (value instanceof BigInteger) {
            bigIntValue = (BigInteger) value;
        } else {
            throw new IllegalArgumentException("Invalid value for type " + type);
        }
        if (!unsigned && bigIntValue.compareTo(BigInteger.ZERO) < 0) {
            bigIntValue = BigInteger.ONE.shiftLeft(bits).add(bigIntValue);
        }
        return leftPad(bigIntValue.toByteArray(), bits / 8);
    }

    private static byte[] packArray(String type, Object value) {
        String baseType = type.substring(0, type.indexOf('['));
        String lengthPart = type.substring(type.indexOf('[') + 1, type.indexOf(']'));
        int expectedLength = -1;
        if (!lengthPart.isEmpty()) {
            expectedLength = Integer.parseInt(lengthPart);
        }
        Object[] array;
        if (value instanceof List) {
            array = ((List<?>) value).toArray();
        } else if (value.getClass().isArray()) {
            array = (Object[]) value;
        } else {
            throw new IllegalArgumentException("Invalid value for array type: " + type);
        }
        if (expectedLength != -1 && array.length != expectedLength) {
            throw new IllegalArgumentException("Invalid array length for type " + type);
        }
        List<byte[]> packedItems = new ArrayList<>();
        for (Object item : array) {
            packedItems.add(pack(baseType, item, true));
        }
        return concatenate(packedItems);
    }

    private static byte[] leftPad(byte[] bytes, int length) {
        byte[] padded = new byte[length];
        int offset = length - bytes.length;
        System.arraycopy(bytes, 0, padded, offset, bytes.length);
        return padded;
    }

    private static byte[] rightPad(byte[] bytes, int length) {
        byte[] padded = new byte[length];
        System.arraycopy(bytes, 0, padded, 0, bytes.length);
        return padded;
    }

    private static byte[] concatenate(List<byte[]> arrays) {
        int totalLength = arrays.stream().mapToInt(arr -> arr.length).sum();
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }

    private static byte[] hexStringToByteArray(String s) {
        if (s.length() % 2 == 1) {
            s = "0" + s;
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                  + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Helper method to convert bytes to hex string (for testing purposes)
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Main method for testing
    public static void main(String[] args) {
        List<String> types = Arrays.asList("address", "uint256", "bool");
        List<Object> values = Arrays.asList("0x407d73d8a49eeb85d32cf465507dd71d507100c1", BigInteger.valueOf(12345), true);
        byte[] hash = SoliditySHA3(types, values);
        System.out.println("Hash: " + bytesToHex(hash));
    }
}
