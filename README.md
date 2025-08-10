# fcrypt

This is a simple Rust program that an encrypt and decrypt any file or directory for safe storage. Personally I use it to encrypt all my files before uploading them to any cloud storage provider.

This program encrypts the file name along with the file contents, therefore output files will have random names but they will get back to original names when you decrypt them.

This program uses a password provided by you to derive the key used to encrypt all the files. Therefore, it goes without saying that the encrypted output an easily be decrypted if your password is not safe.

We use AES-GCM algorithm for encryption which will cause decryption to fail if there is any tampering with the ciphertext. Therefore, you can ensure that your files have not being tampered with as well.

Moreover, we use a separate salt and nonce for each file encrypted, making it difficult for anyone to run dictionary attacks.

The output file structure is as follows:

```
|    Salt    |     Nonce    |  Length of file name in bytes = b |    File Name    |            File Content         |
|  16 bytes  |   12 bytes   |            2 bytes                |     b bytes     |     Rest of the encrypted file  |
 <----    Plaintext   ----> <------------------------ Encrypted with AES GCM -------------------------------------->
```

The key for AES-GCM is derived by using Argon2 algorithm on the user provided password with a randomly geenerated salt during encryption. This salt is then stored in the first 16 bytes of the encrypted file to be used later for decryption.
