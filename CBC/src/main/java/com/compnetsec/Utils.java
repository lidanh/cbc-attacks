package com.compnetsec;

import java.io.*;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

/**
 * Useful cross-projects methods: IO, xor, etc.
 *
 * @author Lidan Hifi
 */
public class Utils {
    /**
     * Write the given byte array to disk
     *
     * @param content
     * @param outputFilename
     */
    public static void writeToFile(final byte[] content, final String outputFilename) throws IOException {
        try {
            FileOutputStream out = new FileOutputStream(outputFilename);
            out.write(content);
            out.close();
        } catch (IOException e) {
            throw new IOException(String.format("Error writing output file: %s", outputFilename));
        }
    }

    /**
     * Read a file as a byte array
     *
     * @param inputFile input file
     * @return the given file data as a byte array
     * @throws IOException
     */
    public static byte[] readFromFileAsByteArray(final String inputFile) throws IOException {
        return readFromFileAsByteArray(inputFile, Integer.MAX_VALUE);
    }

    /**
     * Read max bytes from file as a byte array
     *
     * @param inputFile input file
     * @param maxBytes max bytes to read
     * @return the first maxBytes bytes of the given file, as a byte array
     * @throws IOException
     */
    public static byte[] readFromFileAsByteArray(final String inputFile, final int maxBytes) throws IOException {
        byte[] result = null;
        FileInputStream stream = null;

        try {
            stream = new FileInputStream(new File(inputFile));
            FileChannel channel = stream.getChannel();
            MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, Math.min(channel.size(), maxBytes));

            result = new byte[buffer.capacity()];
            buffer.get(result);
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException(String.format("File not found: %s", inputFile));
        } catch (IOException e) {
            throw new IOException(e.getMessage());
        } finally {
            try {
                if (stream != null) stream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return result;
    }

    /**
     * Remove the extension from a given filename
     * @param filename
     * @return the filename without the extension
     */
    public static String withoutExtension(String filename) {
        return (filename.indexOf('.') >= 0) ? filename.substring(0, filename.lastIndexOf('.')) : filename;
    }

    /**
     * XOR between two given byte arrays
     *
     * @param arr1
     * @param arr2
     * @return
     */
    public static byte[] xor(final byte[] arr1, final byte[] arr2) {
        byte[] result = new byte[Math.max(arr1.length, arr2.length)];

        // arr1 XOR arr2
        for (int i = 0; i < result.length; i++) {
            if (i < arr1.length && i < arr2.length)
                result[i] = (byte)(arr1[i] ^ arr2[i]);
            else if (i < arr1.length)
                result[i] = arr1[i];
            else
                result[i] = arr2[i];
        }

        return result;
    }
}
