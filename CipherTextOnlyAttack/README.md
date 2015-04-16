# Cipher Text Only Attack

> In cryptography, a ciphertext-only attack (COA) or known ciphertext attack is an attack model for cryptanalysis where the attacker is assumed to have access only to a set of ciphertexts. While the attacker has no channel providing access to the plaintext prior to encryption, in all practical ciphertext-only attacks, the attacker still has some knowledge of the plaintext. For instance, the attacker might know the language in which the plaintext is written in or the expected statistical distribution of characters in the plaintext. Standard protocol data and messages are commonly part of the plaintext in many deployed systems and can usually be guessed or known efficiently as part of a ciphertext-only attack on these systems.

More information about this attack [here](http://en.wikipedia.org/wiki/Ciphertext-only_attack).

## Attack algorithms
I implemented two algorithms for this attack: brute force based and genetic algorithm, which is more efficient than the brute force one.

You can find more information about the theory behind the genetic algorithm in [this article](https://www.aaai.org/Papers/FLAIRS/2003/Flairs03-045.pdf) (Ralph Morelli,RalphWalde,"A word-based genetic algorithm for cryptanalysis of short cryptograms",Flairs,2003).