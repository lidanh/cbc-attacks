package com.compnetsec;

import com.compnetsec.cbc.CBCCipher;
import com.compnetsec.cbc.Key;

import java.io.IOException;
import java.util.Properties;

class CBCMain {
    private static final String PROP_KEY_RANGE = "keyrange";
    private static final String PROP_KEY_BLOCK_SIZE = "blocksize";
    private static final Integer DEFAULT_BLOCK_SIZE = 10;

    public static void main(String[] args) {
        final Properties properties = new Properties();

        // read properties File (contains blocksize and keyrange)
        try {
            properties.load(CBCMain.class.getResourceAsStream("/cbc.properties"));
        } catch (IOException e) {
            System.err.println("Properties file was not found!");
            return;
        }

        // validate args
        if ((args.length < 4) || ((!args[0].equals(Operation.ENCRYPTION_PARAM) && !args[0].equals(Operation.DECRYPTION_PARAM)))) {
            printUsage();
            return;
        }

        // run
        run(Operation.parse(args[0]),   // operation (encryption or decryption)
                args[1],    // file
                args[2],    // key file
                properties.getProperty(PROP_KEY_RANGE, Key.keyRange),  // key range
                args[3],     // initial vector file
                Integer.valueOf(properties.getProperty(PROP_KEY_BLOCK_SIZE, DEFAULT_BLOCK_SIZE.toString()))    // block size
        );
    }

    public static void run(final Operation operation,
                           final String file,
                           final String keyFile,
                           final String keyRange,
                           final String initialVectorFile,
                           final int blockSize) {

        // set key range
        Key.keyRange = keyRange;
        System.out.printf("Key Range: %s%n", Key.keyRange);

        System.out.printf("Block Size: %d%n", blockSize);

        try {
            CBCCipher cbc = new CBCCipher(keyFile, initialVectorFile, blockSize);

            if (operation == Operation.ENCRYPTION) {
                // Encryption
                final String outputFile = String.format("%s_encrypted.txt", Utils.withoutExtension(file));

                System.out.println("Encrypting...");
                Utils.writeToFile(cbc.encryptFile(file), outputFile);
                System.out.println(file + " encrypted successfully!");
                System.out.println("Output file: " + outputFile);
            } else if (operation == Operation.DECRYPTION) {
                // Decryption
                final String outputFile = String.format("%s_decrypted.txt", Utils.withoutExtension(file));

                System.out.println("Decrypting...");
                Utils.writeToFile(cbc.decryptFile(file), outputFile);
                System.out.println(file + " decrypted successfully!");
                System.out.println("Output file: " + outputFile);
            }
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  Encryption:    java -jar cbc.jar Encryption <plaintext> <key> <IV>");
        System.out.println("  Decryption:    java -jar cbc.jar Decryption <ciphertext> <key> <IV>");
    }

    public enum Operation {
        ENCRYPTION,
        DECRYPTION;

        public static final String ENCRYPTION_PARAM = "Encryption";
        public static final String DECRYPTION_PARAM = "Decryption";

        public static Operation parse(String s) {
            if (s.equals(ENCRYPTION_PARAM)) {
                return Operation.ENCRYPTION;
            } else if (s.equals(DECRYPTION_PARAM)) {
                return Operation.DECRYPTION;
            } else {
                throw new IllegalArgumentException(String.format("Arguments can be only %s or %s", ENCRYPTION_PARAM, DECRYPTION_PARAM));
            }
        }
    }
}
