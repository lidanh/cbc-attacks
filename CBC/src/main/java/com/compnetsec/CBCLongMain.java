package com.compnetsec;

import com.compnetsec.cbc.Key;

import java.io.IOException;
import java.util.Properties;

class CBCLongMain {
    private static final String PROP_KEY_RANGE = "keyrange";
    private static final String PROP_KEY_BLOCK_SIZE = "blocksize";
    private static final Integer DEFAULT_BLOCK_SIZE = 8128;

    public static void main(String[] args) {
        final Properties properties = new Properties();

        // read properties File (contains blocksize and keyrange)
        try {
            properties.load(CBCMain.class.getResourceAsStream("/cbclong.properties"));
        } catch (IOException e) {
            System.err.println("Properties file was not found!");
            return;
        }

        // validate args
        if ((args.length < 4) || ((!args[0].equals(CBCMain.Operation.ENCRYPTION_PARAM) && !args[0].equals(CBCMain.Operation.DECRYPTION_PARAM)))) {
            printUsage();
            return;
        }

        /**
         * Actually, this one is identical to CBCMain from the first task
         * except the change in the properties file: blocksize is 8128 and not 10,
         * and the key range is different.
         *
         * So fuck it, I'll just change the properties file and let the CBCMain to do the dirty job
         */

        // run
        CBCMain.run(CBCMain.Operation.parse(args[0]),   // operation (encryption or decryption)
                    args[1],    // file
                    args[2],    // key file
                    properties.getProperty(PROP_KEY_RANGE, Key.keyRange),  // key range
                    args[3],     // initial vector file
                    Integer.valueOf(properties.getProperty(PROP_KEY_BLOCK_SIZE, DEFAULT_BLOCK_SIZE.toString()))    // block size
        );
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  Encryption:    java -jar cbc_long.jar Encryption <plaintext> <key> <IV>");
        System.out.println("  Decryption:    java -jar cbc_long.jar Decryption <ciphertext> <key> <IV>");
    }
}
