#ifndef MTP_H_
#define MTP_H_


extern "C" {
#include <inttypes.h>
}
#include "uint256.h"
#include <deque>
#include <vector>

#include "MerkleTreeProof/arith_uint256.h"

namespace mtp
{
    const int8_t L = 64;
    const unsigned T_COST = 1;
    const unsigned M_COST = 1024 * 1024 * 4;
    const unsigned LANES = 4;

    /** Solve the hash problem
     *
     * This function will try different nonce until it finds one such that the
     * computed hash is less than the `target` difficulty.
     *
     * \param input         [in]  Serialized block header
     * \param target        [in]  Target difficulty to achieve
     * \param nonce         [out] Starting nonce and found nonce that satisfied the `target`
     * \param nonce_end     [in] Stop searching for nonce if nonce reaches nonce_end
     * \param hash_root_mtp [out] Root hash of the merkle tree
     * \param block_mtp     [out] Merkle tree leaves against which the hash has
     *                            been computed: L*2 leaves of 1KiB each
     * \param proof_mtp     [out] Merkle proofs for every element in `block_mtp`
     * \param output        [out] Resulting hash value for the given `nonce`
     */
    bool hash(const char* input,
              uint32_t target,
              unsigned int& nonce,
              unsigned int nonce_end,
              uint8_t hash_root_mtp[16],
              uint64_t block_mtp[L*2][128],
              std::deque<std::vector<uint8_t>> proof_mtp[L*3],
              uint256& output);

    /** Verify the given nonce does satisfy the given difficulty
     *
     * This function verifies that the provided `nonce` does produce a hash value
     * that is less than `target`.
     *
     * \param input         [in] Serialized block header
     * \param nonce         [in] Nonce to verify
     * \param hash_root_mtp [in] Root hash of the merkle tree
     * \param block_mtp     [in] Data used to compute hash values
     * \param proof_mtp     [in] Merkle proofs for every element in `block_mtp`;
     *
     * \return `true` if `nonce` is valid, `false` otherwise
     */
    bool verify(const char* input,
                const uint32_t nonce,
                const uint8_t hash_root_mtp[16],
                const uint64_t block_mtp[L*2][128],
                const std::deque<std::vector<uint8_t>> proof_mtp[L*3],
                uint256 *mtpHashValue=nullptr);
}

#endif
