package com.compnetsec.attacks.ciphertextonly;

import com.compnetsec.cbc.Key;

import java.io.IOException;

/**
 * Cipher text only attack
 *
 * In cryptography, a ciphertext-only attack (COA) or known ciphertext attack is
 * an attack model for cryptanalysis where the attacker is assumed to have access
 * only to a set of ciphertexts. While the attacker has no channel providing access
 * to the plaintext prior to encryption, in all practical ciphertext-only attacks,
 * the attacker still has some knowledge of the plaintext.
 *
 * @see <a>http://en.wikipedia.org/wiki/Ciphertext-only_attack</a>
 *
 * @author Lidan Hifi
 */
public interface CipherTextOnlyAttack {
    /**
     * Run the attack and crack the key!
     *
     * @return Yeah baby! we've cracked the key!
     * @throws IOException
     */
    Key attack() throws IOException;
}
