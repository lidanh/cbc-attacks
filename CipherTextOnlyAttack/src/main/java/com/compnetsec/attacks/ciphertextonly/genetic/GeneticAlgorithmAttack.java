package com.compnetsec.attacks.ciphertextonly.genetic;

import com.compnetsec.attacks.ciphertextonly.CipherTextOnlyAttack;
import com.compnetsec.attacks.ciphertextonly.FitnessFunction;
import com.compnetsec.attacks.ciphertextonly.WordBasedFitnessFunction;
import com.compnetsec.cbc.Key;

import java.io.IOException;

/**
 * A Genetic algorithm based cipher text only attack
 *
 * @see <a>http://en.wikipedia.org/wiki/Genetic_algorithm</a>
 * @author Lidan Hifi
 */
public class GeneticAlgorithmAttack implements CipherTextOnlyAttack {
    private final String ciphertextFile, initialVectorFile, unknownPlainLetters, unknownKeyLetters;
    private final Key partialKey;
    private final int blockSize;

    /**
     * Initialize a new genetic algorithm based attack
     *
     * @param ciphertextFile ciphertext file
     * @param initialVectorFile initialize vector file
     * @param blockSize block size
     */
    public GeneticAlgorithmAttack(String ciphertextFile, String initialVectorFile, int blockSize) {
        this(ciphertextFile, initialVectorFile, blockSize, null, Key.keyRange, Key.keyRange);
    }

    /**
     * Initialize a new genetic algorithm based attack
     *
     * @param ciphertextFile ciphertext file
     * @param initialVectorFile initialize vector file
     * @param blockSize block size
     * @param partialKey partial key (if some parts of the key were already found)
     * @param unknownPlainLetters unknown plain letters (the "key" side if the key is described as KEY->VALUE)
     * @param unknownKeyLetters unknwon key letters (the "value" side if the key is described as KEY->VALUE)
     */
    public GeneticAlgorithmAttack(String ciphertextFile,
                                  String initialVectorFile,
                                  int blockSize,
                                  Key partialKey,
                                  String unknownPlainLetters,
                                  String unknownKeyLetters) {
        this.ciphertextFile = ciphertextFile;
        this.initialVectorFile = initialVectorFile;
        this.blockSize = blockSize;
        this.unknownPlainLetters = unknownPlainLetters;
        this.unknownKeyLetters = unknownKeyLetters;
        this.partialKey = partialKey;
    }

    public Key attack() throws IOException {
        // The size of the population (candidate keys calculated in each generation)
        final int populationSize = 16;

        // The maximum number of generations
        final int maxGenerations = 128;

        // The portion of the population that will be retained
        // without change between evolutions
        final float elitismRate = 0.1f;

        // The probability of mutation
        final float mutationRate = 0.2f;

        // The probability of mate
        final float crossoverRate = 0.9f;

        // stop threshold (min fitness score of the chosen key)
        // must be at least 90% of confidence!!!
        final float matchThreshold = 0.9f;
        
        FitnessFunction fitnessFunction = new WordBasedFitnessFunction(ciphertextFile,
                                                                        initialVectorFile,
                                                                        blockSize,
                                                                        partialKey,
                                                                        unknownPlainLetters);

        /* Run the algorithm */
        Population population = new Population(
                populationSize,
                elitismRate,
                mutationRate,
                crossoverRate,
                fitnessFunction,
                unknownKeyLetters);

        Chromosome best = population.getFittest();
        int generation = 1;
        while (generation < maxGenerations && best.getFitness() < matchThreshold) {
            System.out.printf("Generation %d: %s (%s)%n", generation, best.getGene(), best.getFitness());

            // evolve the population by mate and mutate chromosomes live in the population
            population.evolve();

            // get the current generation's fittest chromosome
            best = population.getFittest();
            generation++;
        }
        System.out.printf("Generation %d: %s (%s)   -> SUCCESS!%n", generation, best.getGene(), best.getFitness());

        return fitnessFunction.getKey(best.getGene());
    }
}

