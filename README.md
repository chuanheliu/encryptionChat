# encryptionChat
Use both asymmetric encryptions (RSA) and symmetric encryptions (DES, TEA). In general, asymmetric encryptions are (a lot) slower than symmetric encryptions and using asymmetric cipher on raw data is computationally infeasible. One popular solution is: exchange keys under asymmetric encryptions and then use symmetric ciphers with the keys.
The first task is to exchange a key between the client and server. A public/private key pair for RSA will be provided to you. The client has the public key while your server has the private key. After this stage, both sides will have the key2 for future communications.
