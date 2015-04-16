package com.compnetsec;

import com.compnetsec.attacks.ciphertextonly.CipherTextOnlyAttack;
import com.compnetsec.attacks.ciphertextonly.bruteforce.BruteForceAttack;
import com.compnetsec.attacks.ciphertextonly.genetic.GeneticAlgorithmAttack;
import com.compnetsec.cbc.Key;
import com.google.common.base.Stopwatch;

import java.io.IOException;
import java.util.Properties;

class CipherTextAttackMain {
    private static final String PROP_KEY_RANGE = "keyrange";
    private static final String PROP_KEY_ALGORITHM = "algorithm";
    private static final String PROP_KEY_BLOCK_SIZE = "blocksize";
    private static final Integer DEFAULT_BLOCK_SIZE = 10;
    private static final Properties properties = new Properties();

    static {
        // Read properties file contains the algorithm to run (GA / BruteForce), the block size and the key range
        try {
            properties.load(CipherTextAttackMain.class.getResourceAsStream("/ciphertextattack.properties"));
        } catch (IOException e) {
            System.err.println("Properties file was not found!");
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        // validate args
        if (args.length < 3) {
            printUsage();
            return;
        }

        final String cipherTextFile = args[1];
        final String initialVectorFile = args[2];
        final String outputFile = String.format("%s_key.txt", Utils.withoutExtension(cipherTextFile));

        // set key range from the properties file
        Key.keyRange = properties.getProperty(PROP_KEY_RANGE, Key.keyRange);
        System.out.printf("Key Range: %s%n", Key.keyRange);

        // set block size from the properties file
        final int blockSize = Integer.valueOf(properties.getProperty(PROP_KEY_BLOCK_SIZE, DEFAULT_BLOCK_SIZE.toString()));
        System.out.printf("Block Size: %d%n", blockSize);

        // set the algorithm for attack (GA for genetic, BruteForce for brute for, surprisingly, brute force)
        final String algorithm = properties.getProperty(PROP_KEY_ALGORITHM, "BruteForce");

        CipherTextOnlyAttack attack;
        if (algorithm.equals("GA")) {
            // attack with genetic algorithm
            attack = new GeneticAlgorithmAttack(cipherTextFile, initialVectorFile, blockSize);
        } else {
            // attack with brute force algorithm
            attack = new BruteForceAttack(cipherTextFile, initialVectorFile, blockSize);
        }

        try {
            // measure the attack duration with Google Guava's stopwatch
            Stopwatch stopwatch = Stopwatch.createStarted();

            Key key = attack.attack();
            System.out.println();
            System.out.printf("Total time: %s%n", stopwatch);

            Utils.writeToFile(key.toKeyFileFormat().getBytes(), outputFile);
            System.out.println(key.prettify());
            System.out.printf("Output file: %s%n", outputFile);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar CipherTextAttack.jar Decryption <ciphertext> <IV>");
    }
}
