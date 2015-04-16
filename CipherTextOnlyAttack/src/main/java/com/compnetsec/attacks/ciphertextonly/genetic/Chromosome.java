package com.compnetsec.attacks.ciphertextonly.genetic;

import com.compnetsec.attacks.ciphertextonly.FitnessFunction;
import com.compnetsec.attacks.ciphertextonly.WordBasedFitnessFunction;
import com.compnetsec.cbc.CBCCipher;
import com.compnetsec.cbc.Key;

import java.util.Random;

/**
 * Chromosome, a possible solution (in this algorithm, a candidate key)
 *
 * The candidate key is represented as a string (called gene).
 * the string representation of this key: a->b, b->c, c->a, is bca.
 *
 * The chromosome is immutable, which means chromosome cannot be changed,
 * and new chromosome will be created each change.
 *
 * @see <a>http://en.wikipedia.org/wiki/Genetic_algorithm</a>
 * @author Lidan Hifi
 */
class Chromosome implements Comparable<Chromosome> {
    private final String gene;
    private final WordBasedFitnessFunction.WordBasedFitnessScore fitness;
    private final WordBasedFitnessFunction fitnessFunction;
    private static final Random random = new Random(System.currentTimeMillis());

    /**
     * Create a new chromosome
     *
     * @param gene candidate key as a string
     * @param fitnessFunction
     */
    private Chromosome(String gene, WordBasedFitnessFunction fitnessFunction) {
        this(gene, fitnessFunction, fitnessFunction.calculate(gene));
    }

    /**
     * Create a new chromosome
     *
     * @param gene candidate key as a string
     * @param fitnessFunction
     * @param fitness fitness score
     */
    private Chromosome(String gene, WordBasedFitnessFunction fitnessFunction, WordBasedFitnessFunction.WordBasedFitnessScore fitness) {
        this.gene = gene;
        this.fitnessFunction = fitnessFunction;
        this.fitness = fitness;
    }

    public String getGene() {
        return gene;
    }

    public float getFitness() {
        return fitness.getScore();
    }

    /**
     * Create a mutation of the current chromosome
     * by swapping two letters in its gene
     *
     * @return new chromosome, which is similar to the current but with mutation.
     */
    public Chromosome mutate() {
        char[] arr = gene.toCharArray();

        int from = random.nextInt(arr.length);
        int to;
        do {
            to = random.nextInt(arr.length);
        } while (to == from);

        // swap the letters
        char tmp = arr[to];
        arr[to] = arr[from];
        arr[from] = tmp;

        return new Chromosome(String.valueOf(arr), fitnessFunction);
    }

    /**
     * Crossover two chromosomes, which means two chromosome creates two children.
     * The children has better genes than their parents, means that if p1
     * can decrypt the word ABC (only) and p2 can decrypt DEF (only),
     * c1 and c2 will probably be able to decrypt ABC and DEF too.
     *
     * the result is that the children will have a better fitness score.
     *
     * @param mate other chromosome to mate with
     * @return a chromosome array contains two children, created from this wild sex
     */
    public Chromosome[] mate(Chromosome mate) {
        String parent1 = this.gene;
        String parent2 = mate.gene;
        Key parent1Key = this.fitnessFunction.getKey(parent1);
        Key parent2Key = this.fitnessFunction.getKey(parent2);
        Chromosome[] children = new Chromosome[2];

        Object[] thisDistinctWords = this.fitness.getDistinctWords().toArray();
        Object[] mateDistinctWords = mate.fitness.getDistinctWords().toArray();

        String word1 = (String)thisDistinctWords[random.nextInt(thisDistinctWords.length)];
        String word2 = (String)mateDistinctWords[random.nextInt(mateDistinctWords.length)];
        while (word1.equals(word2)) {
            word2 = (String)mateDistinctWords[random.nextInt(mateDistinctWords.length)];
        }


        // Crossover:
        //      parent1 can decrypt word1 successfully
        //      transform parent2 to decrypt word1 by swapping the corresponding letters in parent1 => child 2 was born!
        String word1EncryptedWithP1 = CBCCipher.applyKey(word1, parent1Key);
        String word1EncryptedWithP2 = CBCCipher.applyKey(word1, parent2Key);
        String c2 = parent2;
        for (int i = 0; i < word1.length(); i++) {
            c2 = swap(c2, word1EncryptedWithP1.charAt(i), word1EncryptedWithP2.charAt(i));
        }

        //      parent2 can decrypt word2 successfully
        //      transform parent1 to decrypt word2 by swapping the corresponding letters in parent2 => child 1 was born!
        String word2EncryptedWithP1 = CBCCipher.applyKey(word2, parent1Key);
        String word2EncryptedWithP2 = CBCCipher.applyKey(word2, parent2Key);
        String c1 = parent1;
        for (int i = 0; i < word2.length(); i++) {
            c1 = swap(c1, word2EncryptedWithP1.charAt(i), word2EncryptedWithP2.charAt(i));
        }


        // Optimization:
        //      If one of the children is identical to one of its parents,
        //      clone the identical parent's fitness.
        //      Otherwise, calculate the fitness.
        //      This optimization fasten the algorithm by 5 times!
        if (c1.equals(this.gene)) {
            children[0] = new Chromosome(c1, fitnessFunction, this.fitness.clone());
        } else if (c1.equals(mate.gene)) {
            children[0] = new Chromosome(c1, fitnessFunction, mate.fitness.clone());
        } else {
            children[0] = new Chromosome(c1, fitnessFunction);
        }

        if (c2.equals(this.gene)) {
            children[1] = new Chromosome(c2, fitnessFunction, this.fitness.clone());
        } else if (c2.equals(mate.gene)) {
            children[1] = new Chromosome(c2, fitnessFunction, mate.fitness.clone());
        } else {
            children[1] = new Chromosome(c2, fitnessFunction);
        }

        return children;
    }

    /**
     * Swap two letters (a and b) in a given string
     *
     * @param text
     * @param a
     * @param b
     * @return
     */
    private static String swap(String text, char a, char b) {
        StringBuilder sb = new StringBuilder(text.length());

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (c == a)
                sb.append(b);
            else if (c == b)
                sb.append(a);
            else
                sb.append(c);
        }

        return sb.toString();
    }

    /**
     * Generate a random chromosome from a baseGene,
     * most of the time the base gene will be the key range
     *
     * @param fitnessFunction
     * @param baseGene
     * @return a new random chromosome
     */
    static Chromosome generateRandom(FitnessFunction fitnessFunction, String baseGene) {
        char[] geneArr = baseGene.toCharArray();

        // Scramble the letters using the standard Fisher-Yates shuffle
        Random random = new Random(System.currentTimeMillis());
        for (int i = 0; i < geneArr.length - 1; i++) {
            int j = random.nextInt(geneArr.length - 1);
            // Swap letters
            char temp = geneArr[i];
            geneArr[i] = geneArr[j];
            geneArr[j] = temp;
        }

        return new Chromosome(String.valueOf(geneArr), (WordBasedFitnessFunction)fitnessFunction);
    }

    @Override
    public String toString() {
        return String.format("%s (%s)", gene, fitness.getScore());
    }

    public int compareTo(Chromosome c) {
        return fitness.compareTo(c.fitness);
    }

    @Override
    public int hashCode() {
        return (gene + fitness).hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Chromosome)) {
            return false;
        }

        Chromosome c = (Chromosome)obj;
        return this.gene.equals(c.gene) && this.fitness == c.fitness;
    }
}
