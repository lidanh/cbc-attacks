package com.compnetsec.cbc;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;

/**
 * Generic key for CBC Cipher
 *
 * @author Lidan Hifi
 */
public class Key {
    // key range
    public static String keyRange = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // key data structure- save the encryption and the decryption for optimization
    private final HashMap<Byte, Byte> encKey;
    private final HashMap<Byte, Byte> decKey;

    /**
     * Create a new, empty key
     */
    public Key() {
        encKey = new HashMap<Byte, Byte>(keyRange.length());
        decKey = new HashMap<Byte, Byte>(keyRange.length());
    }

    @SuppressWarnings("unchecked")
    private Key(HashMap<Byte, Byte> encKey, HashMap<Byte, Byte> decKey) {
        this.encKey = (HashMap<Byte, Byte>)encKey.clone();
        this.decKey = (HashMap<Byte, Byte>)decKey.clone();
    }

    /**
     * Add a pair of (From, To) to the key
     * @param key
     * @param value
     */
    public void put(Byte key, Byte value) {
        this.encKey.put(key, value);
        this.decKey.put(value, key);
    }

    public Byte getOrDefault(Byte key) {
        return this.encKey.containsKey(key) ? this.encKey.get(key) : key;
    }

    public Key flip() {
        return new Key(this.decKey, this.encKey);
    }

    /**
     * Parse a key file, and create a valid key object.
     *
     * The key file must be in the following format:
     * a b
     * b a
     *
     * for (a->b, b->a) key
     *
     * @param filename key filename
     * @return new key object, parsed from the given key file
     */
    public static Key fromFile(final String filename) throws IOException {
        Key result = new Key();
        BufferedReader br = null;

        try {
            String currentLine;

            br = new BufferedReader(new FileReader(filename));

            while ((currentLine = br.readLine()) != null) {
                result.put((byte)currentLine.charAt(0), (byte)currentLine.charAt(2));
            }
        } catch(IOException e) {
            throw new IOException("Error reading key file: " + filename);
        } finally {
            if (br != null) try {
                br.close();
            } catch (IOException e) {
                throw new IOException("Error closing key file: " + filename);
            }
        }

        return result;
    }

    /**
     * Parse a key from a string.
     *
     * The given string representation must be in the following format:
     * dcba
     *
     * for example, if the key range is abcd, this key will be returned:
     * a -> d
     * b -> c
     * c -> b
     * d -> a
     *
     * @param key string representation of the key
     * @return new key object, parsed from the given string
     */
    public static Key fromString(final String key) {
        assert key.length() == Key.keyRange.length();

        Key result = new Key();
        for (int i = 0; i < Key.keyRange.length(); i++) {
            result.put((byte) keyRange.charAt(i), (byte)key.charAt(i));
        }

        return result;
    }


    /************************ String methods *************************************/

    /**
     * Default string representation: as a values corresponded to the key range.
     * for example, if the key range is abcd,
     * and the key is (a -> d, b -> c, c -> b, d -> a)
     * this string will be returned: dcba.
     *
     * @return string representation of the key
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        for (Byte key : encKey.keySet()) {
            sb.append((char)encKey.get(key).byteValue());
        }

        return sb.toString();
    }

    /**
     * Pretty string representation: as a KEY -> VALUE.
     * for example:
     * a -> b
     * c -> d
     *
     * @return string representation of the key
     */
    public String prettify() {
        StringBuilder sb = new StringBuilder();

        for (Byte key : encKey.keySet()) {
            sb.append((char) key.byteValue()).append(" -> ").append((char) encKey.get(key).byteValue()).append("\n");
        }

        return sb.toString();
    }

    /**
     * String representation in key file format
     * for example:
     * a b
     * c d
     * e f
     * g h
     *
     * @return string representation of the key
     */
    public String toKeyFileFormat() {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < Key.keyRange.length(); i++) {
            sb.append(Key.keyRange.charAt(i))
                    .append(" ")
                    .append((char)getOrDefault((byte) Key.keyRange.charAt(i)).byteValue())
                    .append("\n");
        }

        return sb.toString();
    }
}
