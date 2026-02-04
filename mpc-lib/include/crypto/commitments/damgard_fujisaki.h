#ifndef __DAMGARD_FUJISAKI_H__
#define __DAMGARD_FUJISAKI_H__

#include <stdint.h>
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"
#include "crypto/commitments/ring_pedersen.h"
#include "cosigner_export.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/***********************************/
/*   DAMGARD FUJISAKI COMMITMENTS  */
/***********************************/
/**
 * @typedef damgard_fujisaki_private_t
 * @brief Represents a Damgård-Fujisaki private key structure.
 */
typedef struct damgard_fujisaki_private damgard_fujisaki_private_t;

/**
 * @typedef damgard_fujisaki_public_t
 * @brief Represents a Damgård-Fujisaki public key structure.
 */
typedef struct damgard_fujisaki_public damgard_fujisaki_public_t;

/**
 * @brief Generates a Damgård-Fujisaki private key.
 *
 * @param[in] key_len Length of the key in bits.
 * @param[in] dimension Number of dimensions for the key.
 * @param[out] priv Pointer to the generated private key.
 *
 * @return ring_pedersen_status RING_PEDERSEN_SUCCESS if the key is generated successfully, otherwise an error code.
 */
COSIGNER_EXPORT ring_pedersen_status damgard_fujisaki_generate_private_key(const uint32_t key_len, const uint32_t dimension, damgard_fujisaki_private_t** priv);

/**
 * @brief Generates a Damgård-Fujisaki key pair.
 *
 * @param[in] key_len Length of the key in bits.
 * @param[in] dimension Number of dimensions for the key.
 * @param[out] pub Pointer to the generated public key.
 * @param[out] priv Pointer to the generated private key.
 *
 * @return ring_pedersen_status RING_PEDERSEN_SUCCESS if the key pair is generated successfully, otherwise an error code.
 */
COSIGNER_EXPORT ring_pedersen_status damgard_fujisaki_generate_key_pair(const uint32_t key_len, 
                                                                        const uint32_t dimension, 
                                                                        damgard_fujisaki_public_t** pub, 
                                                                        damgard_fujisaki_private_t** priv);

/**
 * @brief Frees a Damgård-Fujisaki public key.
 *
 * @param[in] pub Pointer to the public key to be freed.
 */
COSIGNER_EXPORT void damgard_fujisaki_free_public(damgard_fujisaki_public_t* pub);

/**
 * @brief Frees a Damgård-Fujisaki private key.
 *
 * @param[in] priv Pointer to the private key to be freed.
 */
COSIGNER_EXPORT void damgard_fujisaki_free_private(damgard_fujisaki_private_t* priv);

/**
 * @brief Returns the size of the public key in bits.
 *
 * @param[in] pub Pointer to the public key.
 *
 * @return uint32_t The number of bits of the public key.
 */
COSIGNER_EXPORT uint32_t damgard_fujisaki_public_size(const damgard_fujisaki_public_t* pub);

/**
 * @brief Serializes a Damgård-Fujisaki public key.
 *
 * @param[in] pub Pointer to the public key to be serialized.
 * @param[out] buffer Buffer to store the serialized key.
 * @param[in] buffer_len Length of the buffer.
 * @param[out] real_buffer_len Actual length of the serialized data.
 *
 * @return uint8_t* Pointer to the serialized buffer or NULL on failure.
 */
COSIGNER_EXPORT uint8_t *damgard_fujisaki_public_serialize(const damgard_fujisaki_public_t* pub, 
                                                           uint8_t* buffer, 
                                                           const uint32_t buffer_len, 
                                                           uint32_t* real_buffer_len);

/**
 * @brief Deserializes a Damgård-Fujisaki public key from a buffer.
 *
 * @param[in] buffer Pointer to the buffer containing the serialized key.
 * @param[in] buffer_len Length of the buffer.
 *
 * @return damgard_fujisaki_public_t* Pointer to the deserialized public key or NULL on failure.
 */
COSIGNER_EXPORT damgard_fujisaki_public_t* damgard_fujisaki_public_deserialize(const uint8_t* const buffer, const uint32_t buffer_len);

/**
 * @brief Serializes a Damgård-Fujisaki private key.
 *
 * @param[in] priv Pointer to the private key to be serialized.
 * @param[out] buffer Buffer to store the serialized key.
 * @param[in] buffer_len Length of the buffer.
 * @param[out] real_buffer_len Actual length of the serialized data.
 *
 * @return uint8_t* Pointer to the serialized buffer or NULL on failure.
 */
COSIGNER_EXPORT uint8_t *damgard_fujisaki_private_serialize(const damgard_fujisaki_private_t* priv, 
                                                            uint8_t* buffer, 
                                                            const uint32_t buffer_len, 
                                                            uint32_t* real_buffer_len);

/**
 * @brief Deserializes a Damgård-Fujisaki private key from a buffer.
 *
 * @param[in] buffer Pointer to the buffer containing the serialized key.
 * @param[in] buffer_len Length of the buffer.
 *
 * @return damgard_fujisaki_private_t* Pointer to the deserialized private key or NULL on failure.
 */
COSIGNER_EXPORT damgard_fujisaki_private_t* damgard_fujisaki_private_deserialize(const uint8_t* buffer, uint32_t buffer_len);

/**
 * @brief Retrieves the public key from a given private key.
 *
 * @param[in] priv Pointer to the private key.
 *
 * @return const damgard_fujisaki_public_t* Pointer to the public key. The returned public key must not be freed.
 */
COSIGNER_EXPORT const damgard_fujisaki_public_t* damgard_fujisaki_private_key_get_public(const damgard_fujisaki_private_t* priv); 

/**
 * @brief Generates zero-knowledge proof parameters for Damgård-Fujisaki commitments.
 *
 * @param[in] priv Pointer to the private key.
 * @param[in] aad Pointer to the Additional Authentication Data (AAD).
 * @param[in] aad_len Length of the AAD.
 * @param[in] challenge_bitlen Length of the challenge in bits.
 * @param[out] serialized_proof Buffer to store the serialized proof.
 * @param[in] proof_len Length of the proof buffer.
 * @param[out] proof_real_len Actual length of the serialized proof.
 *
 * @return zero_knowledge_proof_status Status of the zero-knowledge proof generation.
 */
COSIGNER_EXPORT zero_knowledge_proof_status damgard_fujisaki_parameters_zkp_generate(const damgard_fujisaki_private_t* priv, 
                                                                                     const uint8_t* aad, 
                                                                                     const uint32_t aad_len, 
                                                                                     const uint32_t challenge_bitlength, 
                                                                                     uint8_t* serialized_proof, 
                                                                                     const uint32_t proof_len, 
                                                                                     uint32_t* proof_real_len);
                                               
/**
 * @brief Verifies zero-knowledge proof parameters for Damgård-Fujisaki commitments.
 *
 * @param[in] pub Pointer to the public key.
 * @param[in] aad Pointer to the Additional Authentication Data (AAD).
 * @param[in] aad_len Length of the AAD.
 * @param[in] challenge_bitlen Length of the challenge in bits.
 * @param[in] serialized_proof Pointer to the serialized proof.
 * @param[in] proof_len Length of the proof buffer.
 *
 * @return zero_knowledge_proof_status Status of the zero-knowledge proof verification.
 */
COSIGNER_EXPORT zero_knowledge_proof_status damgard_fujisaki_parameters_zkp_verify(const damgard_fujisaki_public_t *pub, 
                                                                                   const uint8_t* aad, 
                                                                                   const uint32_t aad_len, 
                                                                                   const uint32_t challenge_bitlen, 
                                                                                   const uint8_t* serialized_proof, 
                                                                                   const uint32_t proof_len);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__DAMGARD_FUJISAKI_H__