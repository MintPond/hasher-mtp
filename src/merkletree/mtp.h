
#ifndef ZCOIN_MTP_H
#define ZCOIN_MTP_H

#include "merkle-tree.hpp"

#include <immintrin.h>
#include "argon2ref/argon2.h"
#include "argon2ref/core.h"
#include "argon2ref/thread.h"
#include "argon2ref/blake2.h"
#include "argon2ref/blake2-impl.h"
#include "argon2ref/blamka-round-opt.h"
#include "uint256.h"

namespace mtp {

    class CBlock;

    /* Size of MTP proof */
    const unsigned int MTP_PROOF_SIZE = 1471;

    /* Size of MTP block proof size */
    const unsigned int MTP_BLOCK_PROOF_SIZE = 64;

    /* Size of MTP block */
    const unsigned int MTP_BLOCK_SIZE = 140;

    argon2_context init_argon2d_param(const char *input);

    bool solver(
            uint32_t *input,
            uint32_t nonce,
            argon2_instance_t *instance,
            MerkleTree merkle_tree,
            unsigned char *merkle_root,
            uint64_t mtp_block_out[MTP_BLOCK_PROOF_SIZE * 2][128],
            unsigned char *mtp_proof_out,
            unsigned int *mtp_proof_size_out,
            unsigned char *hash_out);

    bool solver_fast(uint32_t nonce, argon2_instance_t *instance,
                             unsigned char *merkle_root, uint32_t *input, uint256 target, uint256 *hash_out = NULL);

    bool verify(const char *input,
                    uint32_t nonce,
                    const uint8_t hash_root_mtp[16],
                    const uint64_t block_mtp[MTP_BLOCK_PROOF_SIZE * 2][128],
                    const std::deque<std::vector<uint8_t>> proof_mtp[MTP_BLOCK_PROOF_SIZE * 3],
                    uint256 *hash_out);

    bool verify_fast(const char *input,
                uint32_t nonce,
                const uint8_t hash_root_mtp[16],
                const uint64_t block_mtp[MTP_BLOCK_PROOF_SIZE * 2][128],
                uint256 *hash_out);

    MerkleTree::Elements init(argon2_instance_t *instance);

}
#endif //ZCOIN_MTP_H
