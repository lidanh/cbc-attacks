package com.compnetsec.attacks.ciphertextonly.bruteforce;

import com.compnetsec.attacks.ciphertextonly.CipherTextOnlyAttack;
import com.compnetsec.attacks.ciphertextonly.FitnessFunction;
import com.compnetsec.attacks.ciphertextonly.WordBasedFitnessFunction;
import com.compnetsec.cbc.Key;

import java.io.IOException;

/**
 * Brute-Force Attack
 *
 * An implementation of a cipher text only attack.
 * It's not so sophisticated, just calculating the fitness
 * of all key range's permutations, and take the best one, based on its fitness score.
 *
 * @see com.compnetsec.attacks.ciphertextonly.CipherTextOnlyAttack
 * @see com.compnetsec.attacks.ciphertextonly.FitnessFunction
 *
 * @author Lidan Hifi
 */
public class BruteForceAttack implements CipherTextOnlyAttack {
    private final String ciphertextFile, initialVectorFile, unknownPlainLetters, unknownKeyLetters;
    private final Key partialKey;
    private final int blockSize;
    private String bestMatch = null;
    private float bestScore = 0;
    private FitnessFunction fitnessFunction;
    private int results = 0;

    /**
     * Initialize a new brute-force attack
     *
     * @param ciphertextFile cipher text file
     * @param initialVectorFile initial vector file
     * @param blockSize block size
     */
    public BruteForceAttack(String ciphertextFile, String initialVectorFile, int blockSize) {
        this(ciphertextFile, initialVectorFile, blockSize, null, Key.keyRange, Key.keyRange);
    }

    /**
     * Initialize a new brute-force attack
     *
     * @param ciphertextFile cipher text file
     * @param initialVectorFile initial vector file
     * @param blockSize block size
     * @param partialKey partial key (if some parts of the key were already found)
     * @param unknownPlainLetters unknown plain letters (the "key" side if the key is described as KEY->VALUE)
     * @param unknownKeyLetters unknwon key letters (the "value" side if the key is described as KEY->VALUE)
     */
    public BruteForceAttack(String ciphertextFile,
                            String initialVectorFile,
                            int blockSize,
                            Key partialKey,
                            String unknownPlainLetters,
                            String unknownKeyLetters) {
        this.blockSize = blockSize;
        this.unknownPlainLetters = unknownPlainLetters;
        this.unknownKeyLetters = unknownKeyLetters;
        this.partialKey = partialKey;
        this.ciphertextFile = ciphertextFile;
        this.initialVectorFile = initialVectorFile;
    }

    @Override
    public Key attack() throws IOException {
        fitnessFunction = new WordBasedFitnessFunction(ciphertextFile, initialVectorFile, blockSize, partialKey, unknownPlainLetters);

        keyPermutation("", unknownKeyLetters);

        return fitnessFunction.getKey(bestMatch);
    }

    /**
     * Generate a string permutations, and calculate its fitness
     * against the given ciphertext and initial vector
     *
     * @param candidate candidate key (or the letters already shuffled)
     * @param str the remaining letters.  if empty- candidate argument is a valid permutation of the key.
     */
    private void keyPermutation(String candidate, String str) {
        if (str.length() > 0) {
            for (int i = 0; i < str.length(); i++)
                // generate permutations
                keyPermutation(candidate + str.charAt(i), str.substring(0, i) + str.substring(i + 1, str.length()));
        } else {
            // calculate the fitness of the candidate key
            results++;
            float currentScore = fitnessFunction.calculate(candidate).getScore();
            System.out.printf("Generation %d: %s (%s)%n", results, candidate, currentScore);

            if (currentScore > bestScore) {
                bestScore = currentScore;
                bestMatch = candidate;
            }
        }
    }
}
