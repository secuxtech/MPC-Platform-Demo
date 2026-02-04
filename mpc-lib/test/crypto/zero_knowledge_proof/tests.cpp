#include "crypto/zero_knowledge_proof/schnorr.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/zero_knowledge_proof/diffie_hellman_log.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "../../../src/common/crypto/paillier/paillier_internal.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"

#include <openssl/rand.h>
#include <openssl/bn.h>

#include <iostream>

#include <string.h>

#include <tests/catch.hpp>

TEST_CASE("schnorr", "[default]") 
{
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();
    elliptic_curve256_algebra_ctx_t* secp256k1_algebra = elliptic_curve256_new_secp256k1_algebra();

    SECTION("verify") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
    }

    SECTION("verify raw data") 
    {
        uint8_t a[32];
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(RAND_bytes(a, sizeof(a)));

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
    }

    SECTION("verify large raw data") 
    {
        uint8_t a[80];
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(RAND_bytes(a, sizeof(a)));

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
    }

    SECTION("invalid public") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_scalar_t a2;
        memcpy(a2, a, sizeof(a));
        a2[sizeof(a2) - 1]++;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a2, sizeof(a2), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid secret") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        a[sizeof(a) - 1]++;

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid id") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        a[sizeof(a) - 1]++;
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid proof") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        zkp.R[sizeof(elliptic_curve256_point_t) - 1]++;
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE((status2 == ZKP_VERIFICATION_FAILED || status2 == ZKP_INVALID_PARAMETER));
        zkp.R[sizeof(elliptic_curve256_point_t) - 1]--;
        zkp.s[sizeof(elliptic_curve256_scalar_t) - 1]++;
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);

        zkp.R[sizeof(elliptic_curve256_point_t) - 1] += 11;
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE((status2 == ZKP_VERIFICATION_FAILED || status2 == ZKP_INVALID_PARAMETER));
    }

    SECTION("custom k") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        elliptic_curve256_scalar_t k;
        elliptic_curve256_point_t R;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_rand(ctx, &k);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)k, sizeof(k), &R);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        REQUIRE(memcmp(zkp.R, R, sizeof(R)) == 0);

        k[sizeof(k) - 1]++;
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        REQUIRE(memcmp(zkp.R, R, sizeof(R)) != 0);

        memcpy(zkp.R, R, sizeof(R));
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);

        memset(k, 0, sizeof(k));
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
    }

    SECTION("invalid param") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, NULL, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate(secp256k1_algebra, a, 0, &a, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), NULL, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, NULL, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, NULL);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);

        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, NULL, sizeof(a), a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, 0, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), NULL, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, 0, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), NULL, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), &A, NULL);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);

        elliptic_curve256_scalar_t k;
        status = GFp_curve_algebra_rand(ctx, &k);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, NULL, sizeof(a), &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, 0, &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), NULL, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, NULL, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, NULL, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, &k, NULL);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);

        status2 = schnorr_zkp_verify(secp256k1_algebra, NULL, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, 0, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), NULL, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, NULL);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
    }

    SECTION("secp256r1") 
    {
        elliptic_curve256_algebra_ctx_t* secp256r1 = elliptic_curve256_new_secp256r1_algebra();
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = secp256r1->rand(secp256r1, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = secp256r1->generator_mul(secp256r1, &A, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256r1, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256r1, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);

        uint8_t b[80];
        elliptic_curve256_point_t B;
        REQUIRE(RAND_bytes(b, sizeof(b)));
        status2 = schnorr_zkp_generate_for_data(secp256r1, b, sizeof(b), b, sizeof(b), &B, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256r1, b, sizeof(b), &B, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        secp256r1->release(secp256r1);
    }

    SECTION("ed25519") 
    {
        elliptic_curve256_algebra_ctx_t* ed25519 = elliptic_curve256_new_ed25519_algebra();
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = ed25519->rand(ed25519, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = ed25519->generator_mul(ed25519, &A, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(ed25519, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(ed25519, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);

        uint8_t b[80];
        elliptic_curve256_point_t B;
        REQUIRE(RAND_bytes(b, sizeof(b)));
        status2 = schnorr_zkp_generate_for_data(ed25519, b, sizeof(b), b, sizeof(b), &B, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(ed25519, b, sizeof(b), &B, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        ed25519->release(ed25519);
    }

    GFp_curve_algebra_ctx_free(ctx);
    secp256k1_algebra->release(secp256k1_algebra);
}

TEST_CASE("ring_pedersen", "verify") 
{
    ring_pedersen_private_t* priv;
    ring_pedersen_public_t* pub;
    auto status = ring_pedersen_generate_key_pair(1024, &pub, &priv);

    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        (*(uint32_t*)proof.get())++;
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
        (*(uint32_t*)proof.get())--;
        proof.get()[32]++;
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("commitment") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint8_t x[32];
        REQUIRE(RAND_bytes(x, sizeof(x)));
        uint8_t r[32];
        REQUIRE(RAND_bytes(r, sizeof(r)));
        uint32_t commitment_len;
        auto res = ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), NULL, 0, &commitment_len);
        REQUIRE(res == RING_PEDERSEN_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> commitment(new uint8_t[commitment_len]);
        res = ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len, &commitment_len);
        REQUIRE(res == RING_PEDERSEN_SUCCESS);
        res = ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len);
        REQUIRE(res == RING_PEDERSEN_SUCCESS);
    }

    SECTION("invalid commitment") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint8_t x[32];
        REQUIRE(RAND_bytes(x, sizeof(x)));
        uint8_t r[32];
        REQUIRE(RAND_bytes(r, sizeof(r)));
        uint32_t commitment_len;
        auto res = ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), NULL, 0, &commitment_len);
        REQUIRE(res == RING_PEDERSEN_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> commitment(new uint8_t[commitment_len]);
        res = ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len, &commitment_len);
        REQUIRE(res == RING_PEDERSEN_SUCCESS);
        x[5]++;
        res = ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len);
        REQUIRE(res == RING_PEDERSEN_INVALID_COMMITMENT);
        x[5]--;
        r[8]++;
        res = ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len);
        REQUIRE(res == RING_PEDERSEN_INVALID_COMMITMENT);
        r[8]--;
        commitment[15]++;
        res = ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len);
        REQUIRE(res == RING_PEDERSEN_INVALID_COMMITMENT);
    }

    SECTION("batch verification") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        const uint32_t BATCH_SIZE = 1000;
        const uint32_t SCALAR_SIZE = 100;
        ring_pedersen_batch_data_t x[BATCH_SIZE];
        ring_pedersen_batch_data_t r[BATCH_SIZE];
        ring_pedersen_batch_data_t commits[BATCH_SIZE];
        uint32_t commitment_len;
        const uint8_t ZERO = 0;
        auto res = ring_pedersen_create_commitment(pub, &ZERO, sizeof(ZERO), &ZERO, sizeof(ZERO), NULL, 0, &commitment_len);

        for (size_t i = 0; i < BATCH_SIZE; i++)
        {
            x[i].size = SCALAR_SIZE;
            r[i].size = SCALAR_SIZE;
            commits[i].size = commitment_len;
            x[i].data = new uint8_t[SCALAR_SIZE];
            REQUIRE(x[i].data);
            REQUIRE(RAND_bytes(x[i].data, SCALAR_SIZE));
            r[i].data = new uint8_t[SCALAR_SIZE];
            REQUIRE(r[i].data);
            REQUIRE(RAND_bytes(r[i].data, SCALAR_SIZE));
            commits[i].data = new uint8_t[commitment_len];
            REQUIRE(commits[i].data);

            res = ring_pedersen_create_commitment(pub, x[i].data, SCALAR_SIZE, r[i].data, SCALAR_SIZE, commits[i].data, commits[i].size, &commitment_len);
            REQUIRE(res == RING_PEDERSEN_SUCCESS);
        }

        clock_t start = clock();
        for (size_t i = 0; i < BATCH_SIZE; i++)
            REQUIRE(ring_pedersen_verify_commitment(priv, x[i].data, x[i].size, r[i].data, r[i].size, commits[i].data, commits[i].size) == RING_PEDERSEN_SUCCESS);
        size_t diff = clock() - start;
        std::cout << "single verifications done in " << std::dec << diff << " " << diff / CLOCKS_PER_SEC << "s" << std::endl;

        start = clock();
        REQUIRE(ring_pedersen_verify_batch_commitments(priv, BATCH_SIZE, x, r, commits) == RING_PEDERSEN_SUCCESS);
        diff = clock() - start;
        std::cout << "batch verification done in " << std::dec << diff << " " << diff / CLOCKS_PER_SEC << "s" << std::endl;

        for (size_t i = 0; i < BATCH_SIZE; i++)
        {
            delete[] x[i].data;
            delete[] r[i].data;
            delete[] commits[i].data;
        }
    }

    SECTION("invalid param") 
    {
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_generate(priv, NULL, sizeof("hello world") - 1, proof.get(), proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), 0, NULL);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        
        res = ring_pedersen_parameters_zkp_verify(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_verify(pub, 0, sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), 7);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
    }

    SECTION("serialization") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t needed_len = 0;
        ring_pedersen_public_serialize(pub, NULL, 0, &needed_len);
        uint8_t* buff = (uint8_t*)malloc(needed_len);
        ring_pedersen_public_serialize(pub, buff, needed_len, &needed_len);
        ring_pedersen_public_t* pub2 = ring_pedersen_public_deserialize(buff, needed_len);
        REQUIRE(pub2);
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = ring_pedersen_parameters_zkp_verify(pub2, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        
        ring_pedersen_private_serialize(priv, NULL, 0, &needed_len);
        buff = (uint8_t*)realloc(buff, needed_len);
        ring_pedersen_private_serialize(priv, buff, needed_len, &needed_len);
        ring_pedersen_private_t* priv2 = ring_pedersen_private_deserialize(buff, needed_len);
        REQUIRE(priv2);
        free(buff);
        res = ring_pedersen_parameters_zkp_generate(priv2, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        ring_pedersen_free_public(pub2);
        ring_pedersen_free_private(priv2);
    }

    ring_pedersen_free_public(pub);
    ring_pedersen_free_private(priv);
}

TEST_CASE("exp_range_proof", "[default]") 
{
    ring_pedersen_public_t*  ring_pedersen_pub;
    ring_pedersen_private_t* ring_pedersen_priv;
    auto status = ring_pedersen_generate_key_pair(1024, &ring_pedersen_pub, &ring_pedersen_priv);
    paillier_public_key_t*  paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    long res = paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv);
    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, &proof) == ZKP_SUCCESS);
        REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof) == ZKP_SUCCESS);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("multiple proofs") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t proof[2];
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        paillier_ciphertext_t* ciphertext = NULL;
        REQUIRE(paillier_encrypt_to_ciphertext(paillier_pub, x, sizeof(elliptic_curve256_scalar_t), &ciphertext) == PAILLIER_SUCCESS);
        paillier_get_ciphertext(ciphertext, NULL, 0, &proof[0].ciphertext_len);
        proof[0].ciphertext = proof[1].ciphertext = new uint8_t[proof[0].ciphertext_len];
        REQUIRE(paillier_get_ciphertext(ciphertext, proof[0].ciphertext, proof[0].ciphertext_len, &proof[1].ciphertext_len) == PAILLIER_SUCCESS);
        REQUIRE(proof[0].ciphertext_len == proof[1].ciphertext_len);

        range_proof_paillier_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, ciphertext, NULL, 0, &proof[0].proof_len);
        proof[0].serialized_proof = new uint8_t[proof[0].proof_len];
        proof[1].serialized_proof = new uint8_t[proof[0].proof_len];
        REQUIRE(range_proof_paillier_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, ciphertext, proof[0].serialized_proof, proof[0].proof_len, &proof[1].proof_len) == ZKP_SUCCESS);
        REQUIRE(proof[0].proof_len == proof[1].proof_len);
        REQUIRE(range_proof_paillier_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, ciphertext, proof[1].serialized_proof, proof[0].proof_len, &proof[1].proof_len) == ZKP_SUCCESS);
        REQUIRE(memcmp(proof[0].serialized_proof, proof[1].serialized_proof, proof[0].proof_len) != 0);
        REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &proof[0]) == ZKP_SUCCESS);
        REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &proof[1]) == ZKP_SUCCESS);
        elliptic_curve256_point_t Xs[2];
        memcpy(Xs[0], X, sizeof(elliptic_curve256_point_t));
        memcpy(Xs[1], X, sizeof(elliptic_curve256_point_t));
        REQUIRE(range_proof_exponent_zkpok_batch_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, 2, Xs, proof) == ZKP_SUCCESS);
        paillier_free_ciphertext(ciphertext);
        delete[] proof[0].ciphertext;
        delete[] proof[0].serialized_proof;
        delete[] proof[1].serialized_proof;
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, &proof) == ZKP_SUCCESS);
        REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"gello world", sizeof("hello world") - 1, &X, proof) == ZKP_VERIFICATION_FAILED);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, &proof) == ZKP_SUCCESS);
        proof->ciphertext[123]++;
        REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof) == ZKP_VERIFICATION_FAILED);
        proof->ciphertext[123]--;
        proof->serialized_proof[55]++;
        REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof) == ZKP_VERIFICATION_FAILED);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("ed25519") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        auto ed25519 = elliptic_curve256_new_ed25519_algebra();
        REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, &proof) == ZKP_SUCCESS);
        REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof) == ZKP_SUCCESS);
        range_proof_free_paillier_with_range_proof(proof);
        ed25519->release(ed25519);
    }

    ring_pedersen_free_public(ring_pedersen_pub);
    ring_pedersen_free_private(ring_pedersen_priv);
    paillier_free_public_key(paillier_pub);
    paillier_free_private_key(paillier_priv);
    algebra->release(algebra);
}

TEST_CASE("exp_range_proof_small_group", "[default]") 
{
    damgard_fujisaki_public*  damgard_fujisaki_pub;
    damgard_fujisaki_private* damgard_fujisaki_priv;
    auto status = damgard_fujisaki_generate_key_pair(1024, 2, &damgard_fujisaki_pub, &damgard_fujisaki_priv);
    REQUIRE(status == RING_PEDERSEN_SUCCESS);
    paillier_commitment_private_key_t* paillier_priv = NULL;
    
    long res = paillier_commitment_generate_private_key(2048, &paillier_priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("valid") 
    {
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                        paillier_priv, 
                                                                        algebra, 
                                                                        (const unsigned char*)"hello world", 
                                                                        sizeof("hello world") - 1, 
                                                                        x, 
                                                                        sizeof(x), 
                                                                        &proof) == ZKP_SUCCESS);

        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                                      paillier_commitment_private_cast_to_public(paillier_priv), 
                                                                      algebra, 
                                                                      (const unsigned char*)"hello world", 
                                                                      sizeof("hello world") - 1, 
                                                                      &X, 
                                                                      reinterpret_cast<const const_paillier_with_range_proof_t*>(proof)) == ZKP_SUCCESS);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("invalid aad") 
    {
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                        paillier_priv, 
                                                                        algebra, 
                                                                        (const unsigned char*)"hello world", 
                                                                        sizeof("hello world") - 1, 
                                                                        x, 
                                                                        sizeof(x), 
                                                                        &proof) == ZKP_SUCCESS);

        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                                      paillier_commitment_private_cast_to_public(paillier_priv), 
                                                                      algebra, 
                                                                      (const unsigned char*)"gello world", 
                                                                      sizeof("gello world") - 1, 
                                                                      &X, 
                                                                      reinterpret_cast<const const_paillier_with_range_proof_t*>(proof)) == ZKP_VERIFICATION_FAILED);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("invalid proof") 
    {
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                        paillier_priv, 
                                                                        algebra, 
                                                                        (const unsigned char*)"hello world", 
                                                                        sizeof("hello world") - 1, 
                                                                        x, 
                                                                        sizeof(x), 
                                                                        &proof) == ZKP_SUCCESS);
        proof->ciphertext[123]++;
        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                                      paillier_commitment_private_cast_to_public(paillier_priv), 
                                                                      algebra, 
                                                                      (const unsigned char*)"hello world", 
                                                                      sizeof("hello world") - 1, 
                                                                      &X, 
                                                                      reinterpret_cast<const const_paillier_with_range_proof_t*>(proof)) == ZKP_VERIFICATION_FAILED);
        proof->ciphertext[123]--;
        proof->serialized_proof[55]++;
        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                                      paillier_commitment_private_cast_to_public(paillier_priv), 
                                                                      algebra, 
                                                                      (const unsigned char*)"hello world", 
                                                                      sizeof("hello world") - 1, 
                                                                      &X, 
                                                                      reinterpret_cast<const const_paillier_with_range_proof_t*>(proof)) == ZKP_VERIFICATION_FAILED);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("secp256r1") 
    {
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        auto secp256r1 = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(secp256r1->rand(secp256r1, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(secp256r1->generator_mul(secp256r1, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                        paillier_priv, 
                                                                        secp256r1, 
                                                                        (const unsigned char*)"hello world", 
                                                                        sizeof("hello world") - 1, 
                                                                        x, 
                                                                        sizeof(x), 
                                                                        &proof) == ZKP_SUCCESS);

        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                                      paillier_commitment_private_cast_to_public(paillier_priv), 
                                                                      secp256r1, 
                                                                      (const unsigned char*)"hello world", 
                                                                      sizeof("hello world") - 1, 
                                                                      &X, 
                                                                      reinterpret_cast<const const_paillier_with_range_proof_t*>(proof)) == ZKP_SUCCESS);
        range_proof_free_paillier_with_range_proof(proof);
        secp256r1->release(secp256r1);
    }

    SECTION("ed25519") 
    {
        elliptic_curve256_scalar_t x;
        elliptic_curve256_point_t X;
        paillier_with_range_proof_t *proof;
        auto ed25519 = elliptic_curve256_new_ed25519_algebra();
        REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                        paillier_priv, 
                                                                        ed25519, 
                                                                        (const unsigned char*)"hello world", 
                                                                        sizeof("hello world") - 1, 
                                                                        x, 
                                                                        sizeof(x), 
                                                                        &proof) == ZKP_SUCCESS);

        REQUIRE(range_proof_paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                                      paillier_commitment_private_cast_to_public(paillier_priv), 
                                                                      ed25519, 
                                                                      (const unsigned char*)"hello world", 
                                                                      sizeof("hello world") - 1, 
                                                                      &X, 
                                                                      reinterpret_cast<const const_paillier_with_range_proof_t*>(proof)) == ZKP_SUCCESS);
        range_proof_free_paillier_with_range_proof(proof);
        ed25519->release(ed25519);
    }

    damgard_fujisaki_free_public(damgard_fujisaki_pub);
    damgard_fujisaki_free_private(damgard_fujisaki_priv);
    paillier_commitment_free_private_key(paillier_priv);
    algebra->release(algebra);
}

TEST_CASE("rddh", "[default]") 
{
    ring_pedersen_public_t*  ring_pedersen_pub;
    ring_pedersen_private_t* ring_pedersen_priv;
    auto status = ring_pedersen_generate_key_pair(1024, &ring_pedersen_pub, &ring_pedersen_priv);
    paillier_public_key_t*  paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    long res = paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv);
    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t X, A, B;
        paillier_with_range_proof_t *proof;

        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, &a, &b, &proof) == ZKP_SUCCESS);
        elliptic_curve256_scalar_t tmp;
        REQUIRE(algebra->mul_scalars(algebra, &tmp, a, sizeof(elliptic_curve256_scalar_t), b, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), x, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_SUCCESS);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t X, A, B;
        paillier_with_range_proof_t *proof;
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, &a, &b, &proof) == ZKP_SUCCESS);
        elliptic_curve256_scalar_t tmp;
        REQUIRE(algebra->mul_scalars(algebra, &tmp, a, sizeof(elliptic_curve256_scalar_t), b, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), x, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"gello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_VERIFICATION_FAILED);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t X, A, B;
        paillier_with_range_proof_t *proof;
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, &a, &b, &proof) == ZKP_SUCCESS);
        elliptic_curve256_scalar_t tmp;
        REQUIRE(algebra->mul_scalars(algebra, &tmp, a, sizeof(elliptic_curve256_scalar_t), b, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), x, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        proof->ciphertext[123]++;
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_VERIFICATION_FAILED);
        proof->ciphertext[123]--;
        proof->serialized_proof[55]++;
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_VERIFICATION_FAILED);
        A[12]++;
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_VERIFICATION_FAILED);
        A[12]--;
        B[11]++;
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_VERIFICATION_FAILED);
        B[11]--;
        X[10]++;
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_VERIFICATION_FAILED);
        tmp[31]++;
        REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_VERIFICATION_FAILED);
        range_proof_free_paillier_with_range_proof(proof);
    }

    SECTION("ed25519") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t X, A, B;
        paillier_with_range_proof_t *proof;
        auto ed25519 = elliptic_curve256_new_ed25519_algebra();
        REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->rand(ed25519, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->rand(ed25519, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(ring_pedersen_pub, paillier_pub, ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, &a, &b, &proof) == ZKP_SUCCESS);
        elliptic_curve256_scalar_t tmp;
        REQUIRE(ed25519->mul_scalars(ed25519, &tmp, a, sizeof(elliptic_curve256_scalar_t), b, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->add_scalars(ed25519, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), x, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof) == ZKP_SUCCESS);
        range_proof_free_paillier_with_range_proof(proof);
        ed25519->release(ed25519);
    }

    ring_pedersen_free_public(ring_pedersen_pub);
    ring_pedersen_free_private(ring_pedersen_priv);
    paillier_free_public_key(paillier_pub);
    paillier_free_private_key(paillier_priv);
    algebra->release(algebra);
}

TEST_CASE("ddh", "[default]") 
{
    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("valid") 
    {
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t base_point, tmp;
        diffie_hellman_log_public_data_t pub;
        diffie_hellman_log_zkp_t proof;

        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &pub.X, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.C, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &tmp, &pub.A, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_points(algebra, &pub.C, &pub.C, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(diffie_hellman_log_zkp_generate(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &x, &a, &b, &pub, &proof) == ZKP_SUCCESS);
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_SUCCESS);
    }

    SECTION("invalid aad") 
    {
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t base_point, tmp;
        diffie_hellman_log_public_data_t pub;
        diffie_hellman_log_zkp_t proof;

        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &pub.X, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.C, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &tmp, &pub.A, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_points(algebra, &pub.C, &pub.C, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(diffie_hellman_log_zkp_generate(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &x, &a, &b, &pub, &proof) == ZKP_SUCCESS);
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"gello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid proof") 
    {
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t base_point, tmp;
        diffie_hellman_log_public_data_t pub;
        diffie_hellman_log_zkp_t proof;

        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &pub.X, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.C, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &tmp, &pub.A, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_points(algebra, &pub.C, &pub.C, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(diffie_hellman_log_zkp_generate(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &x, &a, &b, &pub, &proof) == ZKP_SUCCESS);
        base_point[0] ^= 1;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        base_point[0] ^= 1;
        pub.A[12]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        pub.A[12]--;
        pub.B[11]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        pub.B[11]--;
        pub.C[10]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        pub.C[10]--;
        pub.X[10]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        pub.X[10]--;
        
        proof.D[22]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        proof.D[22]--;
        proof.Y[21]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        proof.Y[21]--;
        proof.V[20]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        proof.V[20]--;
        proof.w[30]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        proof.w[30]--;
        proof.z[31]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
    }

    SECTION("ed25519") 
    {
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t base_point, tmp;
        diffie_hellman_log_public_data_t pub;
        diffie_hellman_log_zkp_t proof;
        auto ed25519 = elliptic_curve256_new_ed25519_algebra();

        REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->point_mul(ed25519, &pub.X, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->rand(ed25519, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &pub.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->rand(ed25519, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &pub.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &pub.C, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->point_mul(ed25519, &tmp, &pub.A, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->add_points(ed25519, &pub.C, &pub.C, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(diffie_hellman_log_zkp_generate(ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &x, &a, &b, &pub, &proof) == ZKP_SUCCESS);
        REQUIRE(diffie_hellman_log_zkp_verify(ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_SUCCESS);
        ed25519->release(ed25519);
    }

    algebra->release(algebra);
}

TEST_CASE("paillier_large_factors", "[default]") 
{
    ring_pedersen_public_t*  ring_pedersen_pub;
    ring_pedersen_private_t* ring_pedersen_priv;
    auto status = ring_pedersen_generate_key_pair(1024, &ring_pedersen_pub, &ring_pedersen_priv);
    paillier_public_key_t*  paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    long res = paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv);
    
    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(paillier_pub, ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof, len) == ZKP_SUCCESS);
        delete[] proof;
    }

    SECTION("valid large keys") 
    {
        ring_pedersen_public_t*  large_ring_pedersen_pub;
        ring_pedersen_private_t* large_ring_pedersen_priv;
        auto status = ring_pedersen_generate_key_pair(2048, &large_ring_pedersen_pub, &large_ring_pedersen_priv);
        paillier_public_key_t*  large_paillier_pub = NULL;
        paillier_private_key_t* large_paillier_priv = NULL;
        long res = paillier_generate_key_pair(3072, &large_paillier_pub, &large_paillier_priv);
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(large_paillier_priv, large_ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(large_paillier_priv, large_ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(large_paillier_pub, large_ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof, len) == ZKP_SUCCESS);
        delete[] proof;
    
        paillier_free_private_key(large_paillier_priv);
        paillier_free_public_key(large_paillier_pub);
        ring_pedersen_free_private(large_ring_pedersen_priv);
        ring_pedersen_free_public(large_ring_pedersen_pub);
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(paillier_pub, ring_pedersen_priv, (const unsigned char*)"gello world", sizeof("hello world") - 1, proof, len) == ZKP_VERIFICATION_FAILED);
        delete[] proof;
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t len = 0;
        BN_CTX* ctx = BN_CTX_new();
        BN_CTX_start(ctx);
        paillier_private_key priv = {};
        priv.p = BN_CTX_get(ctx);
        priv.q = BN_CTX_get(ctx);
        priv.pub.n = BN_CTX_get(ctx);
        REQUIRE(BN_generate_prime_ex(priv.p, 256, 0, NULL, NULL, NULL));
        REQUIRE(BN_generate_prime_ex(priv.q, 2048 - 256, 0, NULL, NULL, NULL));
        REQUIRE(BN_mul(priv.pub.n, priv.p, priv.q, ctx));

        REQUIRE(range_proof_paillier_large_factors_zkp_generate((paillier_private_key_t*)&priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        range_proof_paillier_large_factors_zkp_generate((paillier_private_key_t*)&priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof, len, &len);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify((paillier_public_key_t*)&priv.pub, ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof, len) == ZKP_VERIFICATION_FAILED);
        delete[] proof;
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    paillier_free_private_key(paillier_priv);
    paillier_free_public_key(paillier_pub);
    ring_pedersen_free_private(ring_pedersen_priv);
    ring_pedersen_free_public(ring_pedersen_pub);
}

// We fix the prime 'd' once and for all without impacting the
// security, since its generation takes a very long time.
// To avoid any malicious intent, we took the smallest safe prime of
// PAILLIER_LARGE_FACTOR_QUADRATIC_MAX_BITSIZE_FOR_HARCODED_D bitsize
// this is 2^3460 + 1169115 - first prime to have 3460 digits. 
// found by iterrating over i where p = 2^3460 + 2*i + 1
static const uint8_t hardcoded_d[] = 
{
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0xd6,
    0xdb
};

TEST_CASE("pailler_large_factors_quadratic", "[default][large_factors_quadratic]") 
{
    paillier_public_key* pub;
    paillier_private_key* priv;
    long res = paillier_generate_key_pair(3072, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);
    uint32_t proof_len = 0;

    SECTION("valid") 
    {
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), serialized_proof.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_verify(pub, (const uint8_t*) "Test AAD", 8, serialized_proof.data(), proof_len) == ZKP_SUCCESS);
    }

    SECTION("invalid aad") 
    {
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), serialized_proof.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_verify(pub, (const uint8_t*) "test AAD", 8, serialized_proof.data(), proof_len) == ZKP_VERIFICATION_FAILED);
    }

    SECTION("auto generated d") 
    {   
        paillier_public_key_t* local_pub;
        paillier_private_key_t* local_priv;
        long res = paillier_generate_key_pair(512, &local_pub, &local_priv);
        REQUIRE(res == PAILLIER_SUCCESS);

        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, NULL, 0, NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, NULL, 0, serialized_proof.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_verify(local_pub, (const uint8_t*) "test AAD", 8, serialized_proof.data(), proof_len) == ZKP_VERIFICATION_FAILED);
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }

    SECTION("non-safe prime d") 
    {   
        paillier_public_key_t* local_pub;
        paillier_private_key_t* local_priv;
        long res = paillier_generate_key_pair(512, &local_pub, &local_priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        const uint32_t d_bitsize = range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(local_pub);
        BN_CTX *ctx = BN_CTX_new();
        REQUIRE(ctx);
        BN_CTX_start(ctx);

        BIGNUM* p = BN_CTX_get(ctx);
        BIGNUM* tmp = BN_CTX_get(ctx);
        REQUIRE((p && tmp));
        //generate not a safe prime p
        do
        {
            REQUIRE(BN_generate_prime_ex(p, d_bitsize, 0, NULL, NULL, NULL));
            REQUIRE(BN_rshift1(tmp, p));
            
        } while ( BN_is_prime_ex(tmp, BN_prime_checks, ctx, NULL));
        std::vector<uint8_t> d_buffer(BN_num_bytes(p));
        BN_bn2bin(p, &d_buffer[0]);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);

        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, d_buffer.data(), (uint32_t)d_buffer.size(), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, d_buffer.data(), (uint32_t)d_buffer.size(), serialized_proof.data(), proof_len, NULL) == ZKP_INVALID_PARAMETER);
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }


    SECTION("too small d") 
    {   
        paillier_public_key_t* local_pub;
        paillier_private_key_t* local_priv;
        long res = paillier_generate_key_pair(512, &local_pub, &local_priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        const uint32_t d_bitsize = range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(local_pub);
        BN_CTX *ctx = BN_CTX_new();
        REQUIRE(ctx);
        BN_CTX_start(ctx);
        BIGNUM* p = BN_CTX_get(ctx);
        REQUIRE(p);
        REQUIRE(BN_generate_prime_ex(p, d_bitsize - 1, 1, NULL, NULL, NULL));
        std::vector<uint8_t> d_buffer(BN_num_bytes(p));
        BN_bn2bin(p, &d_buffer[0]);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);

        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, d_buffer.data(), (uint32_t)d_buffer.size(), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, d_buffer.data(), (uint32_t)d_buffer.size(), serialized_proof.data(), proof_len, NULL) == ZKP_INVALID_PARAMETER);
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }

    //Cannot add test that will fail the range proof without failing the sizes of z1 and z2 that depends on the half of the size of n

    paillier_free_private_key(priv);
    paillier_free_public_key(pub);
}

TEST_CASE("pailler_large_factors_quadratic-slow", "[.][slow]") 
{
    //very slow test - disable by default
    SECTION("valid bigger size") 
    {
        uint32_t proof_len = 0;
        paillier_public_key_t* local_pub;
        paillier_private_key_t* local_priv;
        long res = paillier_generate_key_pair(3100, &local_pub, &local_priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), serialized_proof.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_verify(local_pub, (const uint8_t*) "Test AAD", 8, serialized_proof.data(), proof_len) == ZKP_SUCCESS);
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }
}

TEST_CASE("damgard_fujisaki", "[default]") 
{
    damgard_fujisaki_private* priv;
    damgard_fujisaki_public* pub;
    auto status = damgard_fujisaki_generate_key_pair(1024, 2, &pub, &priv);

    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
    }

    SECTION("valid_bigger_challenge") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 25, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 25, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 25, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 25, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        (*(uint32_t*)proof.get())++;
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
        (*(uint32_t*)proof.get())--;
        proof.get()[32]++;
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid param") 
    {
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, NULL, sizeof("hello world") - 1, 1, proof.get(), proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), 0, NULL);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        res = damgard_fujisaki_parameters_zkp_verify(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_verify(pub, 0, sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), 7);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
    }

    SECTION("serialization") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t needed_len = 0;
        damgard_fujisaki_public_serialize(pub, NULL, 0, &needed_len);
        uint8_t* buff = (uint8_t*)malloc(needed_len);
        damgard_fujisaki_public_serialize(pub, buff, needed_len, &needed_len);
        damgard_fujisaki_public* pub2 = damgard_fujisaki_public_deserialize(buff, needed_len);
        REQUIRE(pub2);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub2, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        damgard_fujisaki_private_serialize(priv, NULL, 0, &needed_len);
        buff = (uint8_t*)realloc(buff, needed_len);
        damgard_fujisaki_private_serialize(priv, buff, needed_len, &needed_len);
        damgard_fujisaki_private* priv2 = damgard_fujisaki_private_deserialize(buff, needed_len);
        REQUIRE(priv2);
        free(buff);
        res = damgard_fujisaki_parameters_zkp_generate(priv2, 
                                                       (const unsigned char*)"hello world", 
                                                       sizeof("hello world") - 1, 
                                                       1, 
                                                       proof.get(), 
                                                       proof_len, 
                                                       &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        damgard_fujisaki_free_public(pub2);
        damgard_fujisaki_free_private(priv2);
    }

    damgard_fujisaki_free_public(pub);
    damgard_fujisaki_free_private(priv);
}