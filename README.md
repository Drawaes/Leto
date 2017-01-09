# Leto
A interest learning exercise in producing a TLS 1.3 Library based off the experimental "Pipelines" from CoreFXLabs

Currently uses OpenSsl 1.1 for the crypto part and supports

Hello Retry, and standard Handshake. 

AESxxx-GCM
ECDSA certificates

Key exchanges
1. x25519
2. x448
3. ffdhe8192
4. ffdhe6144
5. ffdhe4096
6. ffdhe3072
7. ffdhe2048

Things I am currently working on

1. EC key exchange
2. PSK/0-RTT
3. CNG Windows Support
4. ChaCha20/Poly Support

This library aims to prove out the use case for Pipelines having a native TLS library and for how TLS 1.3 can be implemented in that library.

Help and submissions are welcome!
