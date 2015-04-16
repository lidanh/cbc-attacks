package com.compnetsec.attacks.knownplaintext;

import com.compnetsec.Utils;
import com.compnetsec.attacks.ciphertextonly.CipherTextOnlyAttack;
import com.compnetsec.attacks.ciphertextonly.bruteforce.BruteForceAttack;
import com.compnetsec.attacks.ciphertextonly.genetic.GeneticAlgorithmAttack;
import com.compnetsec.cbc.Key;

import java.io.IOException;
import java.util.HashSet;

/**
 * Known plain text attack
 *
 * The known-plaintext attack (KPA) is an attack model for cryptanalysis where the attacker
 * has access to both the plaintext (called a crib), and its encrypted version (ciphertext).
 * These can be used to reveal further secret information such as secret keys and code books.
 * @see <a>http://en.wikipedia.org/wiki/Known-plaintext_attack</a>
 *
 * @author Lidan Hifi
 */
public class KnownPlainTextAttack {
    private final String ciphertextFile, initialVectorFile, knownPlaintextFile, knownCiphertextFile, algorithm;
    private final int blockSize;

    /**
     * Initialize a new known plain text attack
     *
     * @param ciphertextFile cipher text file (unknown)
     * @param initialVectorFile initial vector file
     * @param blockSize block size
     * @param knownPlaintextFile known plaintext file
     * @param knownCiphertextFile known ciphertext file
     * @param preferredAlgorithm preferred algorithm for cracking the unknown letters (GA or BruteForce)
     *                           It is "preferred" because if there are 5 unknown letters or less, brute force is more efficient than GA, so it will be chosen.
     */
    public KnownPlainTextAttack(String ciphertextFile, String initialVectorFile, int blockSize, String knownPlaintextFile, String knownCiphertextFile, String preferredAlgorithm) {
        this.ciphertextFile = ciphertextFile;
        this.initialVectorFile = initialVectorFile;
        this.blockSize = blockSize;
        this.knownPlaintextFile = knownPlaintextFile;
        this.knownCiphertextFile = knownCiphertextFile;
        this.algorithm = preferredAlgorithm;
    }

    /**
     * Crack the key!
     *
     * @return
     * @throws IOException
     */
    public Key attack() throws IOException {
        byte[] knownPlaintext = Utils.readFromFileAsByteArray(knownPlaintextFile);
        byte[] knownCiphertext = Utils.readFromFileAsByteArray(knownCiphertextFile);
        byte[] initialVector = Utils.readFromFileAsByteArray(initialVectorFile, blockSize);

        Key candidate = new Key();

        HashSet<Byte> knownPlain = new HashSet<Byte>();
        HashSet<Byte> knownKey = new HashSet<Byte>();

        // calculate the known plaintext after XOR with the initial vector
        String s = new String(Utils.xor(knownPlaintext, initialVector));
        for (char c : Key.keyRange.toCharArray()) {
            int i = s.indexOf(c);
            if (i >= 0) {
                byte key = (byte)c;
                candidate.put(key, knownCiphertext[i]);
                knownPlain.add(key);
                knownKey.add(knownCiphertext[i]);
            }
        }

        // find the remaining (unknown) plain & key letters
        // (plain is the "key" side in KEY->VALUE, and key is the "value" side)
        StringBuilder remainingPlainLetters = new StringBuilder();
        StringBuilder remainingKeyLetters = new StringBuilder();
        for (int i = 0; i < Key.keyRange.length(); i++) {
            char c = Key.keyRange.charAt(i);
            if (!knownPlain.contains((byte)c))
                remainingPlainLetters.append(c);

            if (!knownKey.contains((byte)c))
                remainingKeyLetters.append(c);
        }

        // run a cipher text only attack of the unknown letters
        CipherTextOnlyAttack cipherTextOnlyAttack = getAttackAlgorithm(candidate, remainingPlainLetters.toString(), remainingKeyLetters.toString());
        candidate = cipherTextOnlyAttack.attack();

        return candidate;
    }

    private CipherTextOnlyAttack getAttackAlgorithm(Key candidate, String unknownPlainLetters, String unknownKeyLetters) {
        // optimization
        if (unknownKeyLetters.length() <= 5)
            return new BruteForceAttack(ciphertextFile,
                                        initialVectorFile,
                                        blockSize,
                                        candidate,
                                        unknownPlainLetters,
                                        unknownKeyLetters);

        if (algorithm.equals("GA")) {
            return new GeneticAlgorithmAttack(ciphertextFile,
                                            initialVectorFile,
                                            blockSize,
                                            candidate,
                                            unknownPlainLetters,
                                            unknownKeyLetters);
        } else {
            return new BruteForceAttack(ciphertextFile,
                                        initialVectorFile,
                                        blockSize,
                                        candidate,
                                        unknownPlainLetters,
                                        unknownKeyLetters);
        }
    }
}

