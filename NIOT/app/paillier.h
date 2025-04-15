// Paillier.h
#ifndef PAILLIER_H
#define PAILLIER_H

#include <openssl/bn.h>
#include <openssl/rand.h>

class Paillier {
public:
    BIGNUM *n, *g, *lambda, *mu, *n_sq;
    BN_CTX *ctx;

    Paillier(int keySize);
    ~Paillier();

    void encrypt(BIGNUM *cipher, BIGNUM *plain);
    void simple_encrypt(BIGNUM *cipher, BIGNUM *plain);
    void decrypt(BIGNUM *plain, BIGNUM *cipher);
    void homomorphic_add(BIGNUM *result, BIGNUM *c1, BIGNUM *c2);
    void homomorphic_mult(BIGNUM *result, BIGNUM *cipher, BIGNUM *scalar);

private:
    void L_function(BIGNUM *result, BIGNUM *x, BIGNUM *n, BN_CTX *ctx);
};

#endif // PAILLIER_H