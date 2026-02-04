#include "crypto/commitments/pedersen.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

#include <tests/catch.hpp>


TEST_CASE("test_pedersen_commitmnet")
{
    const uint8_t aad[] = "SOME RANDOM AAD";
    const uint32_t aad_len = sizeof(aad);
    pedersen_commitment_two_generators_t base;
    struct elliptic_curve256_algebra_ctx *ctx = NULL;
    elliptic_curve256_scalar_t a;
    elliptic_curve256_scalar_t b;
    elliptic_curve256_scalar_t c;
    elliptic_curve_commitment_t commitment;
    SECTION("test secp256k1") 
    {
        ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }

    SECTION("test secp256r1") 
    {
        ctx = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }


    SECTION("test stark") 
    {
        ctx = elliptic_curve256_new_stark_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }

    SECTION("test ed25519") 
    {
        ctx = elliptic_curve256_new_ed25519_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }


    SECTION("negative test1") 
    {
        ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        for (int i = 0; i < ctx->point_size(ctx) * 8; ++i)
        {
            commitment[i / 8] ^=  (0x1 << (i % 8)); //flip bit
            REQUIRE(COMMITMENTS_INVALID_COMMITMENT == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
            commitment[i / 8] ^=  (0x1 << (i % 8)); //flip bit back
        }
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }

    SECTION("negative test2") 
    {
        const uint8_t another_aad[] = "ANOTHER AAD";
        const uint32_t another_aad_len = sizeof(another_aad);
        pedersen_commitment_two_generators_t another_base;
        ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&another_base, another_aad, another_aad_len, ctx));

        REQUIRE(COMMITMENTS_INVALID_COMMITMENT == pedersen_commitment_two_generators_verify_commitment(&commitment, &another_base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }


    if (ctx)
    {
        ctx->release(ctx);
    }
}
