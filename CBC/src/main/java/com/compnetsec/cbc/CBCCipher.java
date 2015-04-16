package com.compnetsec.cbc;

import com.compnetsec.Utils;

import java.io.*;
import java.nio.ByteBuffer;

/**
 * CBC Cipher
 * Provides a simple way to encrypt and decrypt files in a CBC mode-of-operation.
 * The encryption is based on substitution.
 *
 * @author Lidan Hifi
 */
public class CBCCipher {
    // save the encryption and decryption keys for optimization
    private Key encKey = null;
    private Key decKey = null;
    private byte[] initialVector = null;
    private final int blockSize;

    /**
     * Create a new CBC Cipher
     *
     * @param keyFile key filename.
     *                The key must be in the following format:
     *                a b
     *                b a
     *                etc.
     * @param initialVectorFile initial vector filename.
     * @param blockSize block size. doesn't have to be the initial vector size, but most of the time they are identical.
     * @throws IOException
     */
    public CBCCipher(final String keyFile, final String initialVectorFile, final int blockSize) throws IOException {
        this(Key.fromFile(keyFile), Utils.readFromFileAsByteArray(initialVectorFile, blockSize), blockSize);
    }

    /**
     * Create a new CBC Cipher
     *
     * @param encKey encryption key
     * @param initialVector initialize vector
     * @param blockSize block size. doesn't have to be the initial vector size, but most of the time they are identical.
     */
    public CBCCipher(final Key encKey, final byte[] initialVector, final int blockSize) {
        // initialize key
        this.encKey = encKey;
        this.decKey = encKey.flip();

        // initialize init vector
        this.initialVector = initialVector;
        this.blockSize = blockSize;
    }

    /**
     * Encrypt file
     *
     * @param plaintextFilename plaintext filename for encryption
     * @return plaintext encrypted as byte array
     * @throws IOException
     */
    public byte[] encryptFile(final String plaintextFilename) throws IOException {
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        BufferedInputStream in = null;

        try {
            byte[] blockBuffer = new byte[blockSize];
            byte[] cipher = initialVector;

            in = new BufferedInputStream(new FileInputStream(plaintextFilename));

            while (in.available() > 0) {
                if (in.available() >= blockSize) {
                    // remaining bytes is at least one block
                    // read one block from file
                    in.read(blockBuffer);
                } else {
                    // padding is needed
                    int totalRead = in.read(blockBuffer);
                    for (int i = totalRead; i < blockSize; i++) blockBuffer[i] = 0;
                }

                // encrypt the block
                cipher = applyKey(Utils.xor(cipher, blockBuffer), encKey);

                // add the ciphered block to the result
                ciphertext.write(cipher);
            }
        } catch (FileNotFoundException e) {
            throw new IOException(String.format("File not found: %s", plaintextFilename));
        } catch(IOException e) {
            throw new IOException(String.format("File error: %s", plaintextFilename));
        } finally {
            if (in != null) try {
                in.close();
            } catch (IOException e) {
                throw new IOException(String.format("Error closing file: %s", plaintextFilename));
            }
        }

        return ciphertext.toByteArray();
    }

    /**
     * Decrypt ciphertext
     *
     * @param ciphertext byte array, contains the ciphertext
     * @return ciphertext decrypted as string
     */
    public byte[] decrypt(final byte[] ciphertext) {
        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        ByteBuffer in = ByteBuffer.wrap(ciphertext);

        byte[] cipherBuffer = new byte[blockSize];
        byte[] blockVector = initialVector;

        while (in.remaining() > 0) {
            if (in.remaining() >= blockSize) {
                // read a single block
                in.get(cipherBuffer);
            } else {
                // read the last block
                in.get(cipherBuffer, 0, in.remaining());
            }

            // decrypt the block, and add the plaintext block to the result
            try {
                plaintext.write(Utils.xor(blockVector, applyKey(cipherBuffer, decKey)));
            } catch (IOException e) {
                e.printStackTrace();
            }

            blockVector = cipherBuffer.clone();
        }

        return plaintext.toByteArray();
    }

    /**
     * Decrypt file
     *
     * @param cipherTextFile ciphertext filename for decryption
     * @return ciphertext file decrypted as string
     * @throws IOException
     */
    public byte[] decryptFile(final String cipherTextFile) throws IOException {
        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        BufferedInputStream in = null;

        try {
            byte[] cipherBuffer = new byte[blockSize];
            byte[] blockVector = initialVector;

            in = new BufferedInputStream(new FileInputStream(cipherTextFile));

            while (in.available() > 0) {
                // read a single block
                in.read(cipherBuffer);

                // decrypt the block
                // and add the plaintext block to the result
                plaintext.write(Utils.xor(blockVector, applyKey(cipherBuffer, decKey)));

                blockVector = cipherBuffer.clone();
            }
        } catch (FileNotFoundException e) {
            throw new IOException(String.format("File not found: %s", cipherTextFile));
        } catch(IOException e) {
            throw new IOException(String.format("File error: %s", cipherTextFile));
        } finally {
            if (in != null) try {
                in.close();
            } catch (IOException e) {
                throw new IOException(String.format("Error closing file: %s", cipherTextFile));
            }
        }

        return plaintext.toByteArray();
    }

    /**
     * Apply the given key on the given byte array
     *
     * @param block
     * @param key
     * @return encrypted/decrypted block as a byte array (after applying the key)
     */
    private byte[] applyKey(final byte[] block, final Key key) {
        byte[] result = new byte[block.length];

        int i = 0;
        for (byte b : block)
            result[i++] = key.getOrDefault(b);

        return result;
    }

    /**
     * Apply the given key on the given string
     *
     * @param text
     * @param key
     * @return encrypted/decrypted block as a string (after applying the key)
     */
    public static String applyKey(final String text, final Key key) {
        StringBuilder sb = new StringBuilder(text.length());

        for (int i = 0; i < text.length(); i++) {
            sb.append((char)(int)key.getOrDefault((byte)text.charAt(i)));
        }

        return sb.toString();
    }
}
