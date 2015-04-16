package com.compnetsec.attacks.ciphertextonly;

import com.compnetsec.Utils;
import com.compnetsec.cbc.CBCCipher;
import com.compnetsec.cbc.Key;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Word based fitness function.
 * Decrypt a window of the given cipher text,
 * and calculate the percentage of the DISTINCT WORDS from all words found in the decrypted text,
 * which are meaningful in english (each word checked against a dictionary of 10,000 english words)
 *
 * @see FitnessFunction
 * @see com.compnetsec.attacks.ciphertextonly.FitnessFunction.FitnessScore
 *
 * @author Lidan Hifi
 */
public class WordBasedFitnessFunction implements FitnessFunction {
    private static final String DICT_FILE = "/english_words.txt";
    private static final int DICT_SIZE = 10000;
    private static final int DECRYPTION_WINDOW_SIZE = 17000; // how many bytes to read in order to calculate the fitness
    private static final Set<String> fitnessDictionary = new HashSet<String>(DICT_SIZE);

    // highly optimized splitter (made by Google), which splits and trims special chars efficiently.
    private static final Pattern specialCharsRegex = Pattern.compile("^[^a-zA-Z]+|[^a-zA-Z]+$");
    private static final CharMatcher specialCharsMatcher =
            new CharMatcher() {
                @Override
                public boolean matches(char c) {
                    return specialCharsRegex.matcher(Character.toString(c)).find();
                }
            }.precomputed();

    private static final Splitter SPLITTER =
            Splitter.on(Pattern.compile("[\\s+\\n+\\r+]"))
                    .trimResults(specialCharsMatcher)
                    .omitEmptyStrings();

    static {
        // init fitnessDictionary on class load, statically!
        try {
            fillDictionary();
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private final byte[] cipherWindow;
    private final byte[] initialVector;
    private final char[] unknownPlainLetters;
    private final Key partialKey;
    private final int blockSize;

    public WordBasedFitnessFunction(String ciphertextFile, String initialVectorFile, int blockSize) throws IOException {
        this(ciphertextFile, initialVectorFile, blockSize, null, null);
    }

    public WordBasedFitnessFunction(String ciphertextFile, String initialVectorFile, int blockSize, Key partialKey, String unknownPlainLetters) throws IOException {
        // load cipher file to memory for high performance
        byte[] ciphertext = Utils.readFromFileAsByteArray(ciphertextFile);
        this.cipherWindow = new byte[Math.min(DECRYPTION_WINDOW_SIZE, ciphertext.length)];
        System.arraycopy(ciphertext, 0, this.cipherWindow, 0, this.cipherWindow.length);
        this.initialVector = Utils.readFromFileAsByteArray(initialVectorFile, blockSize);
        this.partialKey = partialKey;
        this.unknownPlainLetters = (unknownPlainLetters != null) ? unknownPlainLetters.toCharArray() : null;
        this.blockSize = blockSize;
    }

    /**
     * Calculate the fitness score of the given gene (candidate key)
     *
     * @param gene candidate key string representation
     * @return fitness score, contains the number and the distinct words was found
     */
    public WordBasedFitnessScore calculate(String gene) {
        CBCCipher decrypter = new CBCCipher(getKey(gene), initialVector, blockSize);

        Iterator<String> words = SPLITTER.split(new String(decrypter.decrypt(cipherWindow))).iterator();
        HashSet<String> distinctWords = new HashSet<String>();

        while (words.hasNext()) {
            distinctWords.add(words.next().toLowerCase());
        }

        float total = 0;
        for (String word : distinctWords) {
            if (fitnessDictionary.contains(word))
                total++;
        }

        return new WordBasedFitnessScore(total / distinctWords.size(), distinctWords);
    }

    public Key getKey(String gene) {
        if (partialKey != null && unknownPlainLetters != null) {
            for (int i = 0; i < unknownPlainLetters.length; i++) {
                partialKey.put((byte) unknownPlainLetters[i], (byte) gene.charAt(i));
            }

            return partialKey;
        }

        return Key.fromString(gene);
    }

    /**
     * Fill the dictionary with 10,000 words, statically!
     */
    private static void fillDictionary() throws IOException {
        BufferedReader br = null;

        // get from resources folder
        InputStream fstream = WordBasedFitnessScore.class.getResourceAsStream(DICT_FILE);
        br = new BufferedReader(new InputStreamReader(fstream));

        String word;
        while ((word = br.readLine()) != null) {
            fitnessDictionary.add(word.trim());
        }
        if (br != null)
            br.close();
    }

    /**
     * Word based fitness score.
     * combines a numeric score and the distinct words was found.
     *
     * @author Lidan Hifi.
     */
    public static class WordBasedFitnessScore extends FitnessFunction.FitnessScore {
        private final HashSet<String> distinctWords;

        public WordBasedFitnessScore(float score, HashSet<String> distinctWords) {
            super(score);
            this.distinctWords = distinctWords;
        }

        @SuppressWarnings("unchecked")
        private WordBasedFitnessScore(WordBasedFitnessScore other) {
            super(other.getScore());
            this.distinctWords = (HashSet<String>)other.distinctWords.clone();
        }

        public HashSet<String> getDistinctWords() {
            return distinctWords;
        }

        @Override
        public WordBasedFitnessScore clone() {
            return new WordBasedFitnessScore(this);
        }
    }
}
