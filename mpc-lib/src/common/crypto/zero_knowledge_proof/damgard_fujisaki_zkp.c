#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/drng/drng.h"
#include "../commitments/damgard_fujisaki_internal.h"
#include "../algebra_utils/status_convert.h"
#include "../algebra_utils/algebra_utils.h"
#include "zkp_constants_internal.h"

#include <assert.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define DAMGARD_FUJISAKI_STATISTICAL_SECURITY (128)
#define DAMGARD_FUJISAKI_MAX_CHEATING_SUBGROUP (10)
#ifndef MAX 
#define MAX(A, B) ((A) > (B) ? (A) : (B))
#endif
struct damgard_fujisaki_param_proof
{
    BIGNUM *A[DAMGARD_FUJISAKI_STATISTICAL_SECURITY];
    BIGNUM *z[DAMGARD_FUJISAKI_STATISTICAL_SECURITY];
};

static inline long init_damgard_fujisaki_param_zkp(struct damgard_fujisaki_param_proof *proof, BN_CTX *ctx)
{
    for (size_t i = 0; i < DAMGARD_FUJISAKI_STATISTICAL_SECURITY; i++)
    {
        proof->A[i] = BN_CTX_get(ctx);
        proof->z[i] = BN_CTX_get(ctx);
        if (!proof->A[i] || !proof->z[i])
        {
            return ZKP_OUT_OF_MEMORY;
        }

    }
    return ZKP_SUCCESS;
}

static inline uint32_t damgard_fujisaki_compute_required_repetitions(const uint32_t challenge_bitlength, const uint32_t dimension)
{
    assert(dimension != 0);
    if (challenge_bitlength <= 4 || dimension > 2)
    {
        return DAMGARD_FUJISAKI_STATISTICAL_SECURITY;
    }

    uint32_t repetitions = DAMGARD_FUJISAKI_STATISTICAL_SECURITY;
    if (challenge_bitlength < 8)
    {
        switch (dimension)
        {
        case 1: 
            repetitions = 43;
            break;
        case 2: 
            repetitions = 77;
            break; 
        }
    }
    else if (challenge_bitlength < 16)
    {
        switch (dimension)
        {
        case 1: 
            repetitions = 19;
            break;
        case 2: 
            repetitions = 33;
            break; 
        }
    }
    else // challenge_bitlength  16
    {
        switch (dimension)
        {
        case 1: 
            repetitions = 14;
            break;
        case 2: 
            repetitions = 16;
            break; 
        }
    }
    
    return repetitions;
}

static inline uint32_t damgard_fujisaki_param_zkp_serialized_size_internal(const uint32_t n_bitlen, const uint32_t z_bitlen, const uint32_t repetitions)
{
    const uint32_t n_len = (n_bitlen + 7) / 8;
    const uint32_t z_len = (z_bitlen + 7) / 8;
    // two integers are size of n and number of repetitions

    return (n_len + z_len) * repetitions;
}

static void serialize_damgard_fujisaki_param_zkp(const struct damgard_fujisaki_param_proof *proof,
                                                 const uint32_t n_bitlen,
                                                 const uint32_t z_bitlen,
                                                 const uint32_t repetitions,
                                                 uint8_t *serialized_proof)
{
    assert(repetitions <= DAMGARD_FUJISAKI_STATISTICAL_SECURITY);

    uint8_t *ptr = serialized_proof;
    const uint32_t n_len = (n_bitlen + 7) / 8;
    const uint32_t z_len = (z_bitlen + 7) / 8;

    for (uint32_t i = 0; i < repetitions; ++i)
    {
        BN_bn2binpad(proof->A[i], ptr, n_len);
        ptr += n_len;
        BN_bn2binpad(proof->z[i], ptr, z_len);
        ptr += z_len;
    }
}

static int deserialize_damgard_fujisaki_param_zkp(struct damgard_fujisaki_param_proof *proof,
                                                  const uint32_t n_bitlen,
                                                  const uint32_t z_bitlen,
                                                  const uint32_t repetitions,
                                                  const uint8_t *serialized_proof)
{
    assert(repetitions <= DAMGARD_FUJISAKI_STATISTICAL_SECURITY);

    const uint32_t n_len = (n_bitlen + 7) / 8;
    const uint32_t z_len = (z_bitlen + 7) / 8;
    const uint8_t *ptr = serialized_proof;

    for (uint32_t i = 0; i < repetitions; ++i)
    {
        if (!BN_bin2bn(ptr, n_len, proof->A[i]))
        {
            return 0;
        }
        ptr += n_len;

        if (!BN_bin2bn(ptr, z_len, proof->z[i]))
        {
            return 0;
        }
        ptr += z_len;
    }

    return 1;
}



static int genarate_zkp_seed_dimension(const damgard_fujisaki_public_t* pub,
                                       const struct damgard_fujisaki_param_proof *proof,
                                       const uint8_t *aad,
                                       const uint32_t aad_len,
                                       uint8_t *seed)
{
    SHA256_CTX ctx;
    const uint32_t size = (uint32_t)BN_num_bytes(pub->n);
    uint8_t *a = (uint8_t*)malloc(size);

    if (!a)
    {
        goto cleanup;
    }


    SHA256_Init(&ctx);

    if (aad)
    {
        SHA256_Update(&ctx, aad, aad_len);
    }

    if (BN_bn2binpad(pub->n, a, size) < 0)
    {
        goto cleanup;
    }

    SHA256_Update(&ctx, a, size);

    for (uint32_t i = 0; i < pub->dimension; ++i)
    {
        if (BN_bn2binpad(pub->s[i], a, size) < 0)
        {
            goto cleanup;
        }
        SHA256_Update(&ctx, a, size);
    }

    if (BN_bn2binpad(pub->t, a, size) < 0)
    {
        goto cleanup;
    }

    SHA256_Update(&ctx, a, size);

    for (size_t i = 0; i < DAMGARD_FUJISAKI_STATISTICAL_SECURITY; i++)
    {
        if (BN_bn2binpad(proof->A[i], a, size) < 0)
        {
            goto cleanup;
        }
        SHA256_Update(&ctx, a, size);
    }

    SHA256_Final(seed, &ctx);

    free(a);
    return 1;

cleanup:

    free(a);
    return 0;

}

zero_knowledge_proof_status damgard_fujisaki_parameters_zkp_generate(const damgard_fujisaki_private_t *priv,
                                                                     const uint8_t *aad,
                                                                     const uint32_t aad_len,
                                                                     const uint32_t challenge_bitlength,
                                                                     uint8_t *serialized_proof,
                                                                     const uint32_t proof_len,
                                                                     uint32_t *proof_real_len)
{
    drng_t *rng = NULL;
    BIGNUM *challenge_bn = NULL;
    struct damgard_fujisaki_param_proof proof;
    uint32_t needed_proof_len;
    long ret = -1;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    uint8_t challenge_bin[(DAMGARD_FUJISAKI_STATISTICAL_SECURITY+7)/8];
    uint32_t challenge_bytelength = (challenge_bitlength + 7) / 8;
    BN_CTX *ctx = NULL;
    uint32_t repetitions = 0;
    uint32_t key_bitsize;
    uint32_t answer_randomness_bitlen = 0;
    if (!aad || !aad_len || (!serialized_proof && proof_len))
    {
        return ZKP_INVALID_PARAMETER;
    }

    if (!priv)
    {
        return ZKP_INVALID_PARAMETER;
    }

    key_bitsize = (uint32_t)BN_num_bits(priv->pub.n);
    answer_randomness_bitlen =  (2 * ZKPOK_OPTIM_L_SIZE(key_bitsize) +  ZKPOK_OPTIM_NU_SIZE(key_bitsize)) * 8  + challenge_bitlength ;
    // each lambda has 2 * key_security_bits bits. So sum of all lambdas times challage is log2_floor(priv->pub.dimension + 1) + challenge_bitlength
    // we need it to be smaller than the randomness
    assert(ZKPOK_OPTIM_NU_SIZE(key_bitsize) * 8 > log2_floor(priv->pub.dimension + 1)); 
    

    if (challenge_bitlength > DAMGARD_FUJISAKI_STATISTICAL_SECURITY ||
        challenge_bitlength < 1 ||
        key_bitsize < answer_randomness_bitlen)
    {
        return ZKP_INVALID_PARAMETER;
    }

    repetitions = damgard_fujisaki_compute_required_repetitions(challenge_bitlength, priv->pub.dimension);

    assert(repetitions <= DAMGARD_FUJISAKI_STATISTICAL_SECURITY);

    //actual size of the answer bitlen can be one bit more since 
    needed_proof_len = damgard_fujisaki_param_zkp_serialized_size_internal(key_bitsize, answer_randomness_bitlen, repetitions);
    if (proof_real_len)
    {
        *proof_real_len = needed_proof_len;
    }

    if (proof_len < needed_proof_len)
    {
        return ZKP_INSUFFICIENT_BUFFER;
    }

    if (!priv->pub.mont)
    {
        //check only here because mont is not required in there is no enough buffer
        return ZKP_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);

    challenge_bn = BN_CTX_get(ctx);

    if (!challenge_bn)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    ret = init_damgard_fujisaki_param_zkp(&proof, ctx);
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }
    
    ret = -1; //reset ret for OpenSSL errors

    for (uint32_t i = 0; i < repetitions; ++i)
    {
        if (!BN_rand(proof.z[i], answer_randomness_bitlen, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        {
            goto cleanup;
        }
        
        if (!BN_mod_exp_mont(proof.A[i], priv->pub.t, proof.z[i], priv->pub.n, ctx, priv->pub.mont))
        {
            goto cleanup;
        }

    }

    if (!genarate_zkp_seed_dimension(&priv->pub, &proof, aad, aad_len, seed))
    {
        ret = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    ret = convert_drng_to_zkp_status(drng_new(seed, SHA256_DIGEST_LENGTH, &rng));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }


    for (uint32_t i = 0; i < repetitions; ++i)
    {
        for (uint32_t j = 0; j < priv->pub.dimension; ++j)
        {
            ret = convert_drng_to_zkp_status(drng_read_deterministic_rand(rng, challenge_bin, challenge_bytelength));
            if (ret != ZKP_SUCCESS)
            {
                goto cleanup;
            }

            ret = -1; //reset ret for OpenSSL errors

            if (!BN_bin2bn(challenge_bin, challenge_bytelength, challenge_bn))
            {
                goto cleanup;
            }

            BN_mask_bits(challenge_bn, challenge_bitlength); // function never fails or the operand is small enough anyway

            // check that challenge_bn is not zero after masking
            if (!BN_is_zero(challenge_bn))
            {
                // after the modular multiplication, both are smaller than phi(n), BN_mod_add_quick is ok
                if (!BN_mod_mul(challenge_bn, challenge_bn, priv->lamda[j], priv->phi_n, ctx)) 
                {
                    goto cleanup;
                }
                if (!BN_mod_add_quick(proof.z[i], proof.z[i], challenge_bn, priv->phi_n))
                {
                    goto cleanup;
                }
            }
        }
    }

    serialize_damgard_fujisaki_param_zkp(&proof, key_bitsize, answer_randomness_bitlen, repetitions, serialized_proof);
    ret = ZKP_SUCCESS;

cleanup:

    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }

    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

zero_knowledge_proof_status damgard_fujisaki_parameters_zkp_verify(const damgard_fujisaki_public_t *pub,
                                                                   const uint8_t *aad,
                                                                   const uint32_t aad_len,
                                                                   const uint32_t challenge_bitlength,
                                                                   const uint8_t *serialized_proof,
                                                                   const uint32_t proof_len)
{
    drng_t *rng = NULL;
    BIGNUM *t_pow_z, *challenge_bn = NULL;
    struct damgard_fujisaki_param_proof proof;
    long ret = -1;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    uint8_t challenge_bin[(DAMGARD_FUJISAKI_STATISTICAL_SECURITY+7)/8];
    const uint32_t challenge_bytelength = (challenge_bitlength + 7) / 8;
    BN_CTX *ctx = NULL;
    uint32_t repetitions;
    uint32_t key_bitsize;
    uint32_t answer_randomness_bitlen = 0;
    if (!aad || !aad_len || !serialized_proof || !proof_len)
    {
        return ZKP_INVALID_PARAMETER;
    }

    if (!pub || !pub->mont || !pub->dimension)
    {
        return ZKP_INVALID_PARAMETER;
    }

    key_bitsize = (uint32_t)BN_num_bits(pub->n);
    answer_randomness_bitlen =  (2 * ZKPOK_OPTIM_L_SIZE(key_bitsize) +  ZKPOK_OPTIM_NU_SIZE(key_bitsize)) * 8  + challenge_bitlength ;
    // each lambda has 2 * key_security_bits bits. So sum of all lambdas times challage is log2_floor(priv->pub.dimension + 1) + challenge_bitlength
    // we need it to be smaller than the randomness
    assert(ZKPOK_OPTIM_NU_SIZE(key_bitsize) * 8 > log2_floor(pub->dimension + 1)); 
    

    if (challenge_bitlength > DAMGARD_FUJISAKI_STATISTICAL_SECURITY ||
        challenge_bitlength < 1 ||
        key_bitsize < answer_randomness_bitlen)
    {
        return ZKP_INVALID_PARAMETER;
    }

    repetitions = damgard_fujisaki_compute_required_repetitions(challenge_bitlength, pub->dimension);

    assert(repetitions <= DAMGARD_FUJISAKI_STATISTICAL_SECURITY);

    //THIS WILL NOT WORK IF DAMGARD_FUJISAKI_STATISTICAL_SECURITY does not match
    if (proof_len != damgard_fujisaki_param_zkp_serialized_size_internal(key_bitsize, answer_randomness_bitlen, repetitions))
    {
        return ZKP_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);

    ret = init_damgard_fujisaki_param_zkp(&proof, ctx);
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; // reset for OpenSSL errors

    t_pow_z = BN_CTX_get(ctx);
    challenge_bn = BN_CTX_get(ctx);
    if (!t_pow_z || !challenge_bn)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    ret = ZKP_VERIFICATION_FAILED;

    if (BN_is_prime_fasttest_ex(pub->n, 128, ctx, 1, NULL))
    {
        goto cleanup;
    }

    if (is_coprime_fast(pub->n, pub->t, ctx) != 1)
    {
        goto cleanup;
    }

    for (uint32_t i = 0; i < pub->dimension; ++i) 
    {
        if (!is_coprime_fast(pub->s[i], pub->n, ctx))
        {
            goto cleanup;
        }
    }

    if (!deserialize_damgard_fujisaki_param_zkp(&proof, key_bitsize, answer_randomness_bitlen, repetitions, serialized_proof))
    {
        goto cleanup;
    }

    if (!genarate_zkp_seed_dimension(pub, &proof, aad, aad_len, seed))
    {
        ret = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    ret = convert_drng_to_zkp_status(drng_new(seed, SHA256_DIGEST_LENGTH, &rng));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; // reset for OpenSSL
    
    for (uint32_t i = 0; i < repetitions; ++i)
    {
        if ((uint32_t)BN_num_bits(proof.z[i]) > answer_randomness_bitlen)
        {
            ret = ZKP_VERIFICATION_FAILED;
            goto cleanup;
        }

        if (!BN_mod_exp_mont(t_pow_z, pub->t, proof.z[i], pub->n, ctx, pub->mont))
        {
            goto cleanup;
        }

        for (uint32_t j = 0; j < pub->dimension; ++j)
        {
            ret = convert_drng_to_zkp_status(drng_read_deterministic_rand(rng, challenge_bin, challenge_bytelength));
            if (ret != ZKP_SUCCESS)
            {
                goto cleanup;
            }

            ret = -1; // reset for OpenSSL

            if (!BN_bin2bn(challenge_bin, challenge_bytelength, challenge_bn))
            {
                goto cleanup;
            }
            
            BN_mask_bits(challenge_bn, challenge_bitlength); // function never fails or if it fail the operand is small enough

            // check challenge_bn is not zero after masking
            if (!BN_is_zero(challenge_bn))
            {
                if (!BN_mod_exp_mont(challenge_bn, pub->s[j], challenge_bn, pub->n, ctx, pub->mont) ||
                    !BN_mod_mul(proof.A[i], proof.A[i], challenge_bn, pub->n, ctx))
                {
                    goto cleanup;
                }
            }
        }

        if (BN_cmp(t_pow_z, proof.A[i]) != 0)
        {
            ret = ZKP_VERIFICATION_FAILED;
            goto cleanup;
        }

    }
    ret = ZKP_SUCCESS;

cleanup:

    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }

    drng_free(rng);
    
    //the ctx will never be null here
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

