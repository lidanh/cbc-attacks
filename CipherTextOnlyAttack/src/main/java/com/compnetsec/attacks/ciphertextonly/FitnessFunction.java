package com.compnetsec.attacks.ciphertextonly;

import com.compnetsec.cbc.Key;

/**
 * Generic interface for a fitness function.
 *
 * A fitness function is algorithm agnostic, which means
 * it's not tied to a specific algorithm.
 *
 * it's just a way to measure a given candidate key.
 *
 * Example of fitness functions can be word based, letters frequency, etc.
 *
 * @author Lidan Hifi
 */
public interface FitnessFunction {
    /**
     * Calculate the fitness score of a given candidate key
     *
     * @param candidate string representation of the candidate key
     *                  for example, the string representation of this key: a->b, b->c, c->a
     *                  is: bca
     * @return the fitness score of the given candidate key
     */
    FitnessScore calculate(String candidate);

    /**
     * Create a key from a given string representation
     *
     * @param candidate string representation of the candidate key
     *                  for example, the string representation of this key: a->b, b->c, c->a
     *                  is: bca
     * @return key object, parsed from the given string representation
     */
    Key getKey(String candidate);

    /**
     * Generic fitness score.
     *
     */
    class FitnessScore implements Comparable<FitnessScore>, Cloneable {
        private final float score;

        FitnessScore(float score) {
            this.score = score;
        }

        public float getScore() {
            return score;
        }

        @Override
        public int compareTo(FitnessScore f) {
            if (f == null) return -1;

            if (this.score > f.score) {
                return -1;
            } else if (this.score < f.score) {
                return 1;
            }

            return 0;
        }
    }
}
