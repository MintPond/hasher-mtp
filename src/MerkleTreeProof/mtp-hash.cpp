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
    bool hash(const char* input,
              uint32_t target,
              unsigned int& nonce,
              unsigned int nonce_end,
              uint8_t hash_root_mtp[16],
              uint64_t block_mtp[L*2][128],
              std::deque<std::vector<uint8_t>> proof_mtp[L*3],
              uint256& output)
    {

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

        argon2_context context;
        context.out = out;
        context.outlen = OUTLEN;
        context.version = ARGON2_VERSION_NUMBER;
        context.pwd = pwd;
        context.pwdlen = PWDLEN;
        context.salt = salt;
        context.saltlen = SALTLEN;
        context.secret = NULL;
        context.secretlen = SECRETLEN;
        context.ad = NULL;
        context.adlen = ADLEN;
        context.t_cost = T_COST;
        context.m_cost = M_COST;
        context.lanes = LANES;
        context.threads = LANES;
        context.allocate_cbk = NULL;
        context.free_cbk = NULL;
        context.flags = ARGON2_DEFAULT_FLAGS;

#undef OUTLEN
#undef PWDLEN
#undef SALTLEN
#undef SECRETLEN
#undef ADLEN

        uint32_t memory_blocks = context.m_cost;
        if (memory_blocks < (2 * ARGON2_SYNC_POINTS * context.lanes)) {
            memory_blocks = 2 * ARGON2_SYNC_POINTS * context.lanes;
        }
        uint32_t segment_length = memory_blocks / (context.lanes * ARGON2_SYNC_POINTS);
        memory_blocks = segment_length * (context.lanes * ARGON2_SYNC_POINTS);

        argon2_instance_t instance;
        instance.version = context.version;
        instance.memory = NULL;
        instance.passes = context.t_cost;
        instance.memory_blocks = context.m_cost;
        instance.segment_length = segment_length;
        instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
        instance.lanes = context.lanes;
        instance.threads = context.threads;
        instance.type = Argon2_d;
        if (instance.threads > instance.lanes) {
            instance.threads = instance.lanes;
        }

        // step 1
        Argon2CtxMtp(&context, Argon2_d, &instance);

        // step 2
        MerkleTree::Elements elements;
        for (long int i = 0; i < instance.memory_blocks; ++i) {
            uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(instance.memory[i], digest);
            elements.emplace_back(digest, digest + sizeof(digest));
        }

        MerkleTree ordered_tree(elements, true);
        MerkleTree::Buffer root = ordered_tree.getRoot();
        std::copy(root.begin(), root.end(), hash_root_mtp);

        // step 3
        unsigned int n_nonce_internal = nonce;
        TargetHelper const bn_target(target);

        // step 4
        uint256 y[L + 1];
        block blocks[L * 2];
        MerkleTree::Elements proof_blocks[L * 3];
        while (true) {
            if (n_nonce_internal == UINT_MAX) {
                free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));
                return false;
            }

            std::memset(&y[0], 0, sizeof(y));
            std::memset(&blocks[0], 0, sizeof(sizeof(block) * L * 2));

            blake2b_state state;
            blake2b_init(&state, 32); // 256 bit
            blake2b_update(&state, input, 80);
            blake2b_update(&state, hash_root_mtp, MERKLE_TREE_ELEMENT_SIZE_B);
            blake2b_update(&state, &n_nonce_internal, sizeof(unsigned int));
            blake2b_final(&state, &y[0], sizeof(uint256));

            // step 5
            bool init_blocks = false;
            for (uint32_t j = 1; j <= L; ++j) {
                std::string s = "0x" + y[j - 1].GetHex();
                boost::multiprecision::uint256_t t(s);
                uint32_t ij = numeric_cast<uint32_t>(t % M_COST);
                uint32_t except_index = numeric_cast<uint32_t>(M_COST / LANES);
                if (((ij % except_index) == 0) || ((ij % except_index) == 1)) {
                    init_blocks = true;
                    break;
                }

                block blockhash;
                copy_block(&blockhash, &instance.memory[ij]);
                uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
                StoreBlock(&blockhash_bytes, &blockhash);
                blake2b_state ctx_yj;
                blake2b_init(&ctx_yj, 32);
                blake2b_update(&ctx_yj, &y[j - 1], 32);
                blake2b_update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
                blake2b_final(&ctx_yj, &y[j], 32);
                clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
                clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

                //storing blocks
                uint32_t prev_index;
                uint32_t ref_index;
                GetBlockIndex(ij, &instance, &prev_index, &ref_index);
                //previous block
                copy_block(&blocks[(j * 2) - 2], &instance.memory[prev_index]);
                //ref block
                copy_block(&blocks[(j * 2) - 1], &instance.memory[ref_index]);

                //storing proof
                //TODO : make it as function please
                //current proof
                uint8_t digest_curr[MERKLE_TREE_ELEMENT_SIZE_B];
                compute_blake2b(instance.memory[ij], digest_curr);
                MerkleTree::Buffer hash_curr(digest_curr,
                                             digest_curr + sizeof(digest_curr));
                MerkleTree::Elements proof_curr = ordered_tree.getProofOrdered(
                        hash_curr, ij + 1);
                proof_blocks[(j * 3) - 3] = proof_curr;

                //prev proof
                uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];
                compute_blake2b(instance.memory[prev_index], digest_prev);
                MerkleTree::Buffer hash_prev(digest_prev,
                                             digest_prev + sizeof(digest_prev));
                MerkleTree::Elements proof_prev = ordered_tree.getProofOrdered(
                        hash_prev, prev_index + 1);
                proof_blocks[(j * 3) - 2] = proof_prev;

                //ref proof
                uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
                compute_blake2b(instance.memory[ref_index], digest_ref);
                MerkleTree::Buffer hash_ref(digest_ref,
                                            digest_ref + sizeof(digest_ref));
                MerkleTree::Elements proof_ref = ordered_tree.getProofOrdered(
                        hash_ref, ref_index + 1);
                proof_blocks[(j * 3) - 1] = proof_ref;
            }

            if (init_blocks) {
                n_nonce_internal++;
                continue;
            }

            // step 6
            if (UintToArith256(y[L]) > bn_target.m_target) {

                if (n_nonce_internal >= nonce_end) {
                    free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));
                    return false;
                }

                n_nonce_internal++;
                continue;
            }

            break;
        }

        // step 7
        std::copy(root.begin(), root.end(), hash_root_mtp);

        nonce = n_nonce_internal;
        for (int i = 0; i < L * 2; ++i) {
            std::memcpy(block_mtp[i], &blocks[i],
                        sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        }
        for (int i = 0; i < L * 3; ++i) {
            proof_mtp[i] = proof_blocks[i];
        }
        std::memcpy(&output, &y[L], sizeof(uint256));

        //uint8_t h0[ARGON2_PREHASH_SEED_LENGTH];
        //std::memcpy(h0, instance.hash_zero,
        //            sizeof(uint8_t) * ARGON2_PREHASH_SEED_LENGTH);

        // get hash_zero
        //uint8_t h0_computed[ARGON2_PREHASH_SEED_LENGTH];
        //initial_hash(h0_computed, &context, instance.type);

        free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));
        return true;
    }
}
