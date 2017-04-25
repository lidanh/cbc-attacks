# CBC Ciphers and Cryptanalysis Attacks

An implementation of [CBC mode of operation](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.292) (block cipher) in Java.

This project was an assignment in security course, Ben Gurion University, Spring 2015.

![Cipher Block Chaining (CBC) mode encryption](http://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/1202px-CBC_encryption.svg.png)
![Cipher Block Chaining (CBC) mode decryption](http://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/1202px-CBC_decryption.svg.png)

## What's inside?
1. *CBC cipher* with substitution key (long and short but actually there is no difference except the key range and the block size- just because we required to seperate them to different JARs).
2. *Cipher Text Only Attack*- by the obvious way of brute force, **but also by genetic algorithm** which improves the key until it found. this one is for relatively small keys.  [More info about the implementation](https://speakerdeck.com/lidanh/how-did-nature-inspire-me-to-solve-the-ciphertext-only-attack).
3. *Known Plain Text Attack*- which uses the algorithm implemented in task #2 (cipher text only attack) in order to crack larger keys.

## How to build?
`mvn clean package` and you'll get 4 executable JARs in `target` folder of the parent directory, contains the class files and the sources (sorry, assignment requirements...).

## How to test?
There are no JAVA tests (like junit), but you can run a primitive tests script: `./test` to build and run some examples.



### Have Fun!
