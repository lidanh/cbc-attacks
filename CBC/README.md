# CBC Cipher

This project is a demonstration of encryption/decryption in CBC block cipher mode of operation, with a substitution key.

> IBM invented the Cipher Block Chaining (CBC) mode of operation in 1976.[10] In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an initialization vector must be used in the first block.

More information about CBC Block cipher [here](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.292).

![Cipher Block Chaining (CBC) mode encryption](http://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/1202px-CBC_encryption.svg.png)
![Cipher Block Chaining (CBC) mode decryption](http://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/1202px-CBC_decryption.svg.png)

Any parameter of the main application is changeable, just jump to the properties file and change the block size or the key range. The current implementation is a 10 bytes based block, and `abcdefgh` as the key range.