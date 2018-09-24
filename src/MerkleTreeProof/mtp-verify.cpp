#include "mtp.h"
#include "logging.h"
#include "version.h"
#include "arith_uint256.h"
#include "mtp-core.h"

extern "C" {
#include "blake2/blake2.h"
#include "blake2/blake2-impl.h"
#include "blake2/blamka-round-ref.h"
#include "core.h"
#include "ref.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}

#include <iostream>
#include <sstream>
#include <iomanip>
#include "merkle-tree.hpp"
#include "streams.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/numeric/conversion/cast.hpp>

using boost::numeric_cast;
using boost::numeric::bad_numeric_cast;
using boost::numeric::positive_overflow;
using boost::numeric::negative_overflow;

extern int validate_inputs(const argon2_context *context);
extern void clear_internal_memory(void *v, size_t n);

namespace mtp
{

    bool verify(const char* input,
                uint32_t nonce,
                const uint8_t hash_root_mtp[16],
                const uint64_t block_mtp[L*2][128],
                const std::deque<std::vector<uint8_t>> proof_mtp[L*3],
                uint256 *mtpHashValue)
    {

        MerkleTree::Elements proof_blocks[L * 3];
        MerkleTree::Buffer root;
        block blocks[L * 2];
        root.insert(root.begin(), &hash_root_mtp[0], &hash_root_mtp[16]);
        for (int i = 0; i < (L * 3); ++i) {
            proof_blocks[i] = proof_mtp[i];
        }
        for(int i = 0; i < (L * 2); ++i) {
            std::memcpy(blocks[i].v, block_mtp[i],
                        sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        }

#define OUTLEN 32
#define PWDLEN 80
#define SALTLEN 80
#define SECRETLEN 0
#define ADLEN 0

        unsigned char out[OUTLEN];
        unsigned char pwd[PWDLEN];
        std::memcpy(pwd, input, PWDLEN);
        unsigned char salt[SALTLEN];
        std::memcpy(salt, input, SALTLEN);

        argon2_context context_verify;
        context_verify.out = out;
        context_verify.outlen = OUTLEN;
        context_verify.version = ARGON2_VERSION_NUMBER;
        context_verify.pwd = pwd;
        context_verify.pwdlen = PWDLEN;
        context_verify.salt = salt;
        context_verify.saltlen = SALTLEN;
        context_verify.secret = NULL;
        context_verify.secretlen = SECRETLEN;
        context_verify.ad = NULL;
        context_verify.adlen = ADLEN;
        context_verify.t_cost = T_COST;
        context_verify.m_cost = M_COST;
        context_verify.lanes = LANES;
        context_verify.threads = LANES;
        context_verify.allocate_cbk = NULL;
        context_verify.free_cbk = NULL;
        context_verify.flags = ARGON2_DEFAULT_FLAGS;

#undef OUTLEN
#undef PWDLEN
#undef SALTLEN
#undef SECRETLEN
#undef ADLEN

        uint32_t memory_blocks = context_verify.m_cost;
        if (memory_blocks < (2 * ARGON2_SYNC_POINTS * context_verify.lanes)) {
            memory_blocks = 2 * ARGON2_SYNC_POINTS * context_verify.lanes;
        }
        uint32_t segment_length = memory_blocks / (context_verify.lanes * ARGON2_SYNC_POINTS);
        memory_blocks = segment_length * (context_verify.lanes * ARGON2_SYNC_POINTS);

        argon2_instance_t instance;
        instance.version = context_verify.version;
        instance.memory = NULL;
        instance.passes = context_verify.t_cost;
        instance.memory_blocks = context_verify.m_cost;
        instance.segment_length = segment_length;
        instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
        instance.lanes = context_verify.lanes;
        instance.threads = context_verify.threads;
        instance.type = Argon2_d;
        if (instance.threads > instance.lanes) {
            instance.threads = instance.lanes;
        }

        // step 7
        uint256 y[L + 1];
        std::memset(&y[0], 0, sizeof(y));

        blake2b_state state_y0;
        blake2b_init(&state_y0, 32); // 256 bit
        blake2b_update(&state_y0, input, 80);
        blake2b_update(&state_y0, hash_root_mtp, MERKLE_TREE_ELEMENT_SIZE_B);
        blake2b_update(&state_y0, &nonce, sizeof(unsigned int));
        blake2b_final(&state_y0, &y[0], sizeof(uint256));

        // get hash_zero
        uint8_t h0[ARGON2_PREHASH_SEED_LENGTH];
        initial_hash(h0, &context_verify, instance.type);

        // step 8
        for (uint32_t j = 1; j <= L; ++j) {
            // compute ij
            std::string s = "0x" + y[j - 1].GetHex();
            boost::multiprecision::uint256_t t(s);
            uint32_t ij = numeric_cast<uint32_t>(t % M_COST);

            // retrieve x[ij-1] and x[phi(i)] from proof
            block prev_block, ref_block, t_prev_block, t_ref_block;
            std::memcpy(t_prev_block.v, block_mtp[(j * 2) - 2],
                        sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
            std::memcpy(t_ref_block.v, block_mtp[j*2 - 1],
                        sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
            copy_block(&prev_block , &t_prev_block);
            copy_block(&ref_block , &t_ref_block);
            clear_internal_memory(t_prev_block.v, ARGON2_BLOCK_SIZE);
            clear_internal_memory(t_ref_block.v, ARGON2_BLOCK_SIZE);

            //prev_index
            //compute
            uint32_t memory_blocks_2 = M_COST;
            if (memory_blocks_2 < (2 * ARGON2_SYNC_POINTS * LANES)) {
                memory_blocks_2 = 2 * ARGON2_SYNC_POINTS * LANES;
            }

            uint32_t segment_length_2 = memory_blocks_2 / (LANES * ARGON2_SYNC_POINTS);
            uint32_t lane_length = segment_length_2 * ARGON2_SYNC_POINTS;
            uint32_t ij_prev = 0;
            if ((ij % lane_length) == 0) {
                ij_prev = ij + lane_length - 1;
            } else {
                ij_prev = ij - 1;
            }
            if ((ij % lane_length) == 1) {
                ij_prev = ij - 1;
            }

            //hash[prev_index]
            uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(prev_block, digest_prev);
            MerkleTree::Buffer hash_prev(digest_prev,
                                         digest_prev + sizeof(digest_prev));
            if (!MerkleTree::checkProofOrdered(proof_blocks[(j * 3) - 2],
                                               root, hash_prev, ij_prev + 1)) {
                //LogPrintf("error : checkProofOrdered in x[ij_prev]\n");
                return false;
            }

            //compute ref_index
            uint64_t prev_block_opening = prev_block.v[0];
            uint32_t ref_lane = static_cast<uint32_t>((prev_block_opening >> 32) % LANES);
            uint32_t pseudo_rand = static_cast<uint32_t>(prev_block_opening & 0xFFFFFFFF);
            uint32_t lane = ij / lane_length;
            uint32_t slice = (ij - (lane * lane_length)) / segment_length_2;
            uint32_t pos_index = ij - (lane * lane_length)
                                 - (slice * segment_length_2);
            if (slice == 0) {
                ref_lane = lane;
            }

            argon2_instance_t instance;
            instance.segment_length = segment_length_2;
            instance.lane_length = lane_length;

            argon2_position_t position { 0, lane , (uint8_t)slice, pos_index };
            uint32_t ref_index = IndexBeta(&instance, &position, pseudo_rand,
                                           ref_lane == position.lane);

            uint32_t computed_ref_block = (lane_length * ref_lane) + ref_index;

            uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(ref_block, digest_ref);
            MerkleTree::Buffer hash_ref(digest_ref, digest_ref + sizeof(digest_ref));
            if (!MerkleTree::checkProofOrdered(proof_blocks[(j * 3) - 1],
                                               root, hash_ref, computed_ref_block + 1)) {
                //LogPrintf("error : checkProofOrdered in x[ij_ref]\n");
                return false;
            }

            // compute x[ij]
            block block_ij;
            fill_block_mtp(&blocks[(j * 2) - 2], &blocks[(j * 2) - 1],
                           &block_ij, 0, computed_ref_block, h0);

            // verify opening
            // hash x[ij]
            uint8_t digest_ij[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(block_ij, digest_ij);
            MerkleTree::Buffer hash_ij(digest_ij, digest_ij + sizeof(digest_ij));

            if (!MerkleTree::checkProofOrdered(proof_blocks[(j * 3) - 3], root,
                                               hash_ij, ij + 1)) {
                //LogPrintf("error : checkProofOrdered in x[ij]\n");
                return false;
            }

            // compute y(j)
            block blockhash;
            copy_block(&blockhash, &block_ij);
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            StoreBlock(&blockhash_bytes, &blockhash);
            blake2b_state ctx_yj;
            blake2b_init(&ctx_yj, 32);
            blake2b_update(&ctx_yj, &y[j - 1], 32);
            blake2b_update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
            blake2b_final(&ctx_yj, &y[j], 32);
            clear_internal_memory(block_ij.v, ARGON2_BLOCK_SIZE);
            clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
        }

        // step 9
        for (int i = 0; i < (L * 2); ++i) {
            clear_internal_memory(blocks[i].v, ARGON2_BLOCK_SIZE);
        }

        if (mtpHashValue)
            *mtpHashValue = y[L];

        return true;
    }
}