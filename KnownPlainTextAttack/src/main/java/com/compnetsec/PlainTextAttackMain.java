package com.compnetsec;

import com.compnetsec.attacks.knownplaintext.KnownPlainTextAttack;
import com.compnetsec.cbc.Key;
import com.google.common.base.Stopwatch;

import java.io.IOException;
import java.util.Properties;

class PlainTextAttackMain {
    private static final String PROP_KEY_RANGE = "keyrange";
    private static final String PROP_KEY_ALGORITHM = "preferred_algorithm";
    private static final String PROP_KEY_BLOCK_SIZE = "blocksize";
    private static final Integer DEFAULT_BLOCK_SIZE = 8128;

    public static void main(String[] args) {
        final Properties properties = new Properties();

        // Read properties file contains the algorithm to run (GA / BruteForce), the block size and the key range
        try {
            properties.load(PlainTextAttackMain.class.getResourceAsStream("/knownplaintext.properties"));
        } catch (IOException e) {
            System.err.println("Properties file was not found!");
            return;
        }

        // validate args
        if (args.length < 4) {
            printUsage();
            return;
        }

        final String knownPlaintextFile = args[0];
        final String knownCiphertextFile = args[1];
        final String ciphertextFile = args[2];
        final String initialVectorFile = args[3];
        final String outputFile = String.format("%s_key.txt", Utils.withoutExtension(ciphertextFile));

        // set key range from the properties file
        Key.keyRange = properties.getProperty(PROP_KEY_RANGE, Key.keyRange);
        System.out.printf("Key Range: %s%n", Key.keyRange);

        // set block size from the properties file
        final int blockSize = Integer.valueOf(properties.getProperty(PROP_KEY_BLOCK_SIZE, DEFAULT_BLOCK_SIZE.toString()));
        System.out.printf("Block Size: %d%n", blockSize);

        // create the attack
        KnownPlainTextAttack attack = new KnownPlainTextAttack(ciphertextFile,
                                                                initialVectorFile,
                                                                blockSize,
                                                                knownPlaintextFile,
                                                                knownCiphertextFile,
                                                                properties.getProperty(PROP_KEY_ALGORITHM, "BruteForce"));

        try {
            // measure the attack duration with Google Guava's stopwatch
            Stopwatch stopwatch = Stopwatch.createStarted();

            Key key = attack.attack();

            System.out.println();
            System.out.printf("Total time: %s%n", stopwatch);

            Utils.writeToFile(key.toKeyFileFormat().getBytes(), outputFile);
            System.out.println(key);
            System.out.printf("Output file: %s%n", outputFile);
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar PlainTextAttack.jar <known-plain> <known-cipher> <ciphertext> <IV>");
    }
}

