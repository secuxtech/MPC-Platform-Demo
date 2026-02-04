#ifndef __PEDERSEN_H__
#define __PEDERSEN_H__

#include "commitments.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "cosigner_export.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus


typedef elliptic_curve256_point_t elliptic_curve_commitment_t;

/**
 * @struct pedersen_commitment_two_generators
 * @brief Represents two elliptic curve points used for generating Pedersen commitments.
 *
 * @var pedersen_commitment_two_generators::h
 * The first elliptic curve point used in the commitment.
 *
 * @var pedersen_commitment_two_generators::f
 * The second elliptic curve point used in the commitment.
 */
typedef struct pedersen_commitment_two_generators
{
    elliptic_curve256_point_t h;
    elliptic_curve256_point_t f;
} pedersen_commitment_two_generators_t;

/**
 * @brief Generates two elliptic curve points based on input AAD.
 *
 * This function generates two elliptic curve points deterministically from the given Additional Authentication Data (AAD).
 * The points are generated in a manner such that both parties using the same AAD can derive the same points.
 *
 * @param[out] base Pointer to the structure to store the generated elliptic curve points.
 * @param[in] aad Pointer to the Additional Authentication Data (AAD).
 * @param[in] aad_len Length of the AAD.
 * @param[in] ctx Pointer to the elliptic curve algebra context used for operations.
 *
 * @return commitments_status COMMITMENTS_SUCCESS if the points are generated successfully, otherwise an error code.
 */
COSIGNER_EXPORT commitments_status pedersen_commitment_two_generators_base_generate(pedersen_commitment_two_generators_t* base, 
                                                                                    const uint8_t* aad, 
                                                                                    const uint32_t aad_len, 
                                                                                    const struct elliptic_curve256_algebra_ctx *ctx);

/**
 * @brief Creates a Pedersen commitment using the provided generators and scalars.
 *
 * This function computes a Pedersen commitment of the form g^a.h^b.f^c, using the provided elliptic curve points and scalars.
 *
 * @param[out] commitment Pointer to the commitment to be generated.
 * @param[in] base Pointer to the base structure containing elliptic curve points (g, h, f).
 * @param[in] a Pointer to the scalar 'a'.
 * @param[in] a_len Length of the scalar 'a'.
 * @param[in] b Pointer to the scalar 'b'.
 * @param[in] b_len Length of the scalar 'b'.
 * @param[in] c Pointer to the scalar 'c'.
 * @param[in] c_len Length of the scalar 'c'.
 * @param[in] ctx Pointer to the elliptic curve algebra context used for operations.
 *
 * @return commitments_status COMMITMENTS_SUCCESS if the commitment is generated successfully, otherwise an error code.
 */
COSIGNER_EXPORT commitments_status pedersen_commitment_two_generators_create_commitment(elliptic_curve_commitment_t* commitment, 
                                                                                        const pedersen_commitment_two_generators_t* base, 
                                                                                        const uint8_t* a, 
                                                                                        const uint32_t a_len, 
                                                                                        const uint8_t* b, 
                                                                                        const uint32_t b_len, 
                                                                                        const uint8_t* c, 
                                                                                        const uint32_t c_len, 
                                                                                        const struct elliptic_curve256_algebra_ctx *ctx);

/**
 * @brief Verifies a Pedersen commitment using the provided generators and scalars.
 *
 * This function verifies if the given commitment matches the computed value using the provided base points and scalars.
 *
 * @param[in] commitment Pointer to the commitment to be verified.
 * @param[in] base Pointer to the base structure containing elliptic curve points (g, h, f).
 * @param[in] a Pointer to the scalar 'a'.
 * @param[in] a_len Length of the scalar 'a'.
 * @param[in] b Pointer to the scalar 'b'.
 * @param[in] b_len Length of the scalar 'b'.
 * @param[in] c Pointer to the scalar 'c'.
 * @param[in] c_len Length of the scalar 'c'.
 * @param[in] ctx Pointer to the elliptic curve algebra context used for operations.
 *
 * @return commitments_status COMMITMENTS_SUCCESS if the commitment is verified successfully, COMMITMENTS_INVALID_COMMITMENT if verification fails, otherwise an error code.
 */
COSIGNER_EXPORT commitments_status pedersen_commitment_two_generators_verify_commitment(const elliptic_curve_commitment_t* commitment, 
                                                                                        const pedersen_commitment_two_generators_t* base, 
                                                                                        const uint8_t* a, 
                                                                                        const uint32_t a_len, 
                                                                                        const uint8_t* b, 
                                                                                        const uint32_t b_len, 
                                                                                        const uint8_t* c, 
                                                                                        const uint32_t c_len, 
                                                                                        const struct elliptic_curve256_algebra_ctx *ctx);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__PEDERSEN_H__