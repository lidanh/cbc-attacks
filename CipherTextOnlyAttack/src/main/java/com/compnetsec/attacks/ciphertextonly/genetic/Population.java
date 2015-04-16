package com.compnetsec.attacks.ciphertextonly.genetic;

import com.compnetsec.attacks.ciphertextonly.FitnessFunction;

import java.util.Arrays;
import java.util.Random;

/**
 * Population, a collection of chromosomes which is improved each iteration.
 *
 * @see <a>http://en.wikipedia.org/wiki/Genetic_algorithm</a>
 * @author Lidan Hifi
 */
class Population {
    private static final Random random = new Random(System.currentTimeMillis());

    /* Algorithm Parameters */
    private final float elitismRate, mutationRate, crossoverRate;

    private Chromosome[] population;

    /**
     * Initialize a new algorithm population
     *
     * @param populationSize The size of the population
     * @param elitismRate The portion of the population that will be retained without change between evolutions
     * @param mutationRate The probability of mutation
     * @param crossoverRate The probability of mate
     * @param fitnessFunction fitness function used to calculate the fitness of each chromosome
     * @param unknownKeyLetters unknown key letters, which means the search space of the algorithm
     */
    public Population(int populationSize,
                      float elitismRate,
                      float mutationRate,
                      float crossoverRate,
                      FitnessFunction fitnessFunction,
                      String unknownKeyLetters) {
        this.elitismRate = elitismRate;
        this.mutationRate = mutationRate;
        this.crossoverRate = crossoverRate;

        this.population = new Chromosome[populationSize];
        for (int i = 0; i < populationSize; i++) {
            this.population[i] = Chromosome.generateRandom(fitnessFunction, unknownKeyLetters);
        }

        Arrays.sort(population);
    }

    /**
     * Evolve the population, which means create a new generation of the current population
     */
    public void evolve() {
        Chromosome[] newGeneration = new Chromosome[population.length];

        // Copy over a portion of the current generation population unchanged,
        // based on the elitism rate
        int i = Math.round(population.length * elitismRate);
        System.arraycopy(population, 0, newGeneration, 0, i);

        // Iterate over the remainder
        while (i < newGeneration.length) {
            if (random.nextFloat() <= crossoverRate) {
                // Perform a crossover
                int parent1Index = random.nextInt(population.length);
                int parent2Index;
                do { parent2Index = random.nextInt(population.length); } while (parent1Index == parent2Index);

                Chromosome parent1 = population[parent1Index];
                Chromosome parent2 = population[parent2Index];
                Chromosome[] children = parent1.mate(parent2);

                childbirth(children[0], newGeneration, i);
                i++;
                if (i < newGeneration.length) {
                    childbirth(children[1], newGeneration, i);
                }
            } else {
                // No crossover
                childbirth(population[i], newGeneration, i);
            }

            i++;
        }

        // Sort the generation based on fitness
        Arrays.sort(newGeneration);

        // Replace the current population with the new generation
        population = newGeneration;
    }

    /**
     * Chromosome birth.
     * can be a mutation of the given chromosome, or the given chromosome itself.
     *
     * @param chromosome
     * @param generation
     * @param index
     */
    private void childbirth(Chromosome chromosome, Chromosome[] generation, int index) {
        if (random.nextFloat() <= mutationRate) {
            // mutate the chromosome
            generation[index] = chromosome.mutate();
        } else {
            // copy it unchanged
            generation[index] = chromosome;
        }
    }

    /**
     * Get the fittest chromosome in the population, which is always the first
     * element in the sorted array
     *
     * @return the fittest chromosome in the population
     */
    public Chromosome getFittest() {
        return this.population[0];
    }
}
