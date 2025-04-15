#include "paillier.h"
#include <iostream>

Paillier::Paillier(int keySize) {
    ctx = BN_CTX_new();
    BIGNUM *p = BN_new(), *q = BN_new(), *phi = BN_new();
    n = BN_new(); g = BN_new(); lambda = BN_new(); mu = BN_new();n_sq = BN_new();

    BN_generate_prime_ex(p, keySize / 2, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(q, keySize / 2, 1, NULL, NULL, NULL);
    BN_mul(n, p, q, ctx);
    BN_mul(n_sq, n, n, ctx);
    BIGNUM *p1 = BN_new(), *q1 = BN_new(), *gcd = BN_new();
    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());
    BN_gcd(gcd, p1, q1, ctx);
    BIGNUM *phi_mul = BN_new();
	BN_mul(phi_mul, p1, q1, ctx);
	BN_div(lambda, NULL, phi_mul, gcd, ctx);
	BN_free(phi_mul);
    BN_copy(g, n);
    BN_add_word(g, 1);
    BIGNUM *g_lambda = BN_new(), *L_val = BN_new();
    BN_mod_exp(g_lambda, g, lambda, n_sq, ctx);
    L_function(L_val, g_lambda, n, ctx);
    BN_mod_inverse(mu, L_val, n, ctx);

    BN_free(p); BN_free(q);  BN_free(phi);
    BN_free(p1); BN_free(q1); BN_free(gcd);
    BN_free(g_lambda); BN_free(L_val);
}

Paillier::~Paillier() {
    BN_free(n); BN_free(g); BN_free(lambda); BN_free(mu);
    BN_CTX_free(ctx);
}

void Paillier::L_function(BIGNUM *result, BIGNUM *x, BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *temp = BN_new();
    BN_sub(temp, x, BN_value_one());
    BN_div(result, NULL, temp, n, ctx);
    BN_free(temp);
}

void Paillier::encrypt(BIGNUM *cipher, BIGNUM *plain) {
    BIGNUM *r = BN_new(),  *g_r = BN_new(), *n_m = BN_new();
    BN_rand_range(r, n);
    BN_mod_exp(n_m, g, plain, n_sq, ctx);
    BN_mod_exp(g_r, r, n, n_sq, ctx);
    BN_mod_mul(cipher, n_m, g_r, n_sq, ctx);
    BN_free(r); BN_free(g_r); BN_free(n_m);
}

void Paillier::simple_encrypt(BIGNUM *cipher, BIGNUM *plain) {
    BN_mod_exp(cipher, g, plain, n_sq, ctx);
}

void Paillier::decrypt(BIGNUM *plain, BIGNUM *cipher) {
    BIGNUM *c_lambda = BN_new(), *L_val = BN_new();
    BN_mod_exp(c_lambda, cipher, lambda, n_sq, ctx);
    L_function(L_val, c_lambda, n, ctx);
    BN_mod_mul(plain, L_val, mu, n, ctx);


    BN_free(c_lambda); BN_free(L_val);
}

void Paillier::homomorphic_add(BIGNUM *result, BIGNUM *c1, BIGNUM *c2) {
    BN_mod_mul(result, c1, c2, n_sq, ctx);

}

void Paillier::homomorphic_mult(BIGNUM *result, BIGNUM *cipher, BIGNUM *scalar) {

    
    BN_mod_exp(result, cipher, scalar, n_sq, ctx);

}