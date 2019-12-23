//
//
//#pragma once 
#include "mtp.h"
#include "sha3/sph_blake.h"
#include "argon2ref/core.h" // for mtp_verify

#include "argon2ref/blamka-round-ref.h" // for mtp_verifys
#include "argon2ref/blake2-impl.h"
#include "argon2ref/blake2.h"

#ifdef _MSC_VER
#include <windows.h>
#include <winbase.h> /* For SecureZeroMemory */
#endif

#include <ios>
#include <stdio.h>
#include <iostream>
#if defined __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#define memcost 4*1024*1024

namespace mtp {

    static const unsigned int d_mtp = 1;
    static const uint8_t L = 64;
    static const unsigned int memory_cost = memcost;
    static const unsigned T_COST = 1;
    static const unsigned M_COST = 1024 * 1024 * 4;
    static const unsigned LANES = 4;


    uint32_t index_beta(const argon2_instance_t *instance,
                        const argon2_position_t *position, uint32_t pseudo_rand,
                        int same_lane) {

        uint32_t reference_area_size;
        uint64_t relative_position;
        uint32_t start_position, absolute_position;

        if (0 == position->pass) {
            /* First pass */
            if (0 == position->slice) {
                /* First slice */
                reference_area_size =
                        position->index - 1; /* all but the previous */
            } else {
                if (same_lane) {
                    /* The same lane => add current segment */
                    reference_area_size =
                            position->slice * instance->segment_length +
                            position->index - 1;
                } else {
                    reference_area_size =
                            position->slice * instance->segment_length +
                            ((position->index == 0) ? (-1) : 0);
                }
            }
        } else {
            /* Second pass */
            if (same_lane) {
                reference_area_size = instance->lane_length -
                                      instance->segment_length + position->index -
                                      1;
            } else {
                reference_area_size = instance->lane_length -
                                      instance->segment_length +
                                      ((position->index == 0) ? (-1) : 0);
            }
        }

        /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
        * relative position */
        relative_position = pseudo_rand;
        relative_position = relative_position * relative_position >> 32;
        relative_position = reference_area_size - 1 -
                            (reference_area_size * relative_position >> 32);

        /* 1.2.5 Computing starting position */
        start_position = 0;

        if (0 != position->pass) {
            start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
                             ? 0
                             : (position->slice + 1) * instance->segment_length;
        }

        /* 1.2.6. Computing absolute position */
        absolute_position = (start_position + relative_position) %
                            instance->lane_length; /* absolute position */
        return absolute_position;
    }


    void StoreBlock(void *output, const block *src) {
        for (unsigned i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
            store64(static_cast<uint8_t *>(output)
                    + (i * sizeof(src->v[i])), src->v[i]);
        }
    }


    void compute_blake2b(const block &input,
                         uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B]) {
        ablake2b_state state;
        ablake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
        ablake2b4rounds_update(&state, input.v, ARGON2_BLOCK_SIZE);
        ablake2b4rounds_final(&state, digest, MERKLE_TREE_ELEMENT_SIZE_B);
    }


    void getblockindex(uint32_t ij, argon2_instance_t *instance,
                       uint32_t *out_ij_prev, uint32_t *out_computed_ref_block) {

        uint32_t ij_prev = 0;
        if (ij % instance->lane_length == 0)
            ij_prev = ij + instance->lane_length - 1;
        else
            ij_prev = ij - 1;

        if (ij % instance->lane_length == 1)
            ij_prev = ij - 1;

        uint64_t prev_block_opening = instance->memory[ij_prev].v[0];
        uint32_t ref_lane = (uint32_t) ((prev_block_opening >> 32) % instance->lanes);

        uint32_t pseudo_rand = (uint32_t) (prev_block_opening & 0xFFFFFFFF);

        uint32_t Lane = ((ij) / instance->lane_length);
        uint32_t Slice = (ij - (Lane * instance->lane_length)) / instance->segment_length;
        uint32_t posIndex = ij - Lane * instance->lane_length - Slice * instance->segment_length;


        uint32_t rec_ij =
                Slice * instance->segment_length + Lane * instance->lane_length + (ij % instance->segment_length);

        if (Slice == 0)
            ref_lane = Lane;


        argon2_position_t position = {0, Lane, (uint8_t) Slice, posIndex};

        uint32_t ref_index = index_beta(instance, &position, pseudo_rand, ref_lane == position.lane);

        uint32_t computed_ref_block = instance->lane_length * ref_lane + ref_index;

        *out_ij_prev = ij_prev;
        *out_computed_ref_block = computed_ref_block;
    }


    unsigned int trailing_zeros(char str[64]) {

        unsigned int i, d;
        d = 0;
        for (i = 63; i > 0; i--) {
            if (str[i] == '0') {
                d++;
            } else {
                break;
            }
        }
        return d;
    }


    unsigned int trailing_zeros_little_endian(char str[64]) {

        unsigned int i, d;
        d = 0;
        for (i = 0; i < 64; i++) {
            if (str[i] == '0') {
                d++;
            } else {
                break;
            }
        }
        return d;
    }

    unsigned int trailing_zeros_little_endian_uint256(uint256 hash) {
        unsigned int i, d;
        std::string temp = hash.GetHex();
        d = 0;
        for (i = 0; i < temp.size(); i++) {
            if (temp[i] == '0') {
                d++;
            } else {
                break;
            }
        }
        return d;
    }


    static void store_block(void *output, const block *src) {

        unsigned i;
        for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
            store64((uint8_t *) output + i * sizeof(src->v[i]), src->v[i]);
        }
    }


    void fill_block(__m128i *state, const block *ref_block, block *next_block, int with_xor) {

        __m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
        unsigned int i;

        if (with_xor) {
            for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
                state[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) ref_block->v + i));
                block_XY[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) next_block->v + i));
            }
        } else {
            for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
                block_XY[i] = state[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) ref_block->v + i));
            }
        }

        for (i = 0; i < 8; ++i) {
            BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                         state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                         state[8 * i + 6], state[8 * i + 7]);
        }

        for (i = 0; i < 8; ++i) {
            BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                         state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                         state[8 * 6 + i], state[8 * 7 + i]);
        }

        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            state[i] = _mm_xor_si128(state[i], block_XY[i]);
            _mm_storeu_si128((__m128i *) next_block->v + i, state[i]);
        }
    }


    void fill_block2(__m128i *state, const block *ref_block, block *next_block, int with_xor, uint32_t block_header[4]) {

        __m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
        unsigned int i;

        if (with_xor) {
            for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
                state[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) ref_block->v + i));
                block_XY[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) next_block->v + i));
            }
        } else {
            for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
                block_XY[i] = state[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) ref_block->v + i));
            }
        }

        memcpy(&state[8], block_header, sizeof(__m128i));

        for (i = 0; i < 8; ++i) {
            BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                         state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                         state[8 * i + 6], state[8 * i + 7]);
        }

        for (i = 0; i < 8; ++i) {
            BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                         state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                         state[8 * 6 + i], state[8 * 7 + i]);
        }

        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            state[i] = _mm_xor_si128(state[i], block_XY[i]);
            _mm_storeu_si128((__m128i *) next_block->v + i, state[i]);
        }
    }


    void fill_block2_withIndex(__m128i *state, const block *ref_block, block *next_block, int with_xor,
                               uint32_t *block_header/*[8]*/, uint64_t blockIndex) {

        __m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
        unsigned int i;
        uint64_t TheIndex[2] = {0, blockIndex};
        if (with_xor) {
            for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
                state[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) ref_block->v + i));
                block_XY[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) next_block->v + i));
            }
        } else {
            for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
                block_XY[i] = state[i] = _mm_xor_si128(
                        state[i], _mm_loadu_si128((const __m128i *) ref_block->v + i));
            }
        }
        memcpy(&state[7], TheIndex, sizeof(__m128i));
        memcpy(&state[8], block_header, sizeof(__m128i));
        memcpy(&state[9], block_header + 4, sizeof(__m128i));
        for (i = 0; i < 8; ++i) {
            BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                         state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                         state[8 * i + 6], state[8 * i + 7]);
        }

        for (i = 0; i < 8; ++i) {
            BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                         state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                         state[8 * 6 + i], state[8 * 7 + i]);
        }

        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            state[i] = _mm_xor_si128(state[i], block_XY[i]);
            _mm_storeu_si128((__m128i *) next_block->v + i, state[i]);
        }
    }

/*
 * Function fills a new memory block and optionally XORs the old block over the new one.
 * @next_block must be initialized.
 * @param prev_block Pointer to the previous block
 * @param ref_block Pointer to the reference block
 * @param next_block Pointer to the block to be constructed
 * @param with_xor Whether to XOR into the new block (1) or just overwrite (0)
 * @pre all block pointers must be valid
 */
    static void fill_block_mtp(const block *prev_block, const block *ref_block,
                               block *next_block, int with_xor, uint32_t block_index, uint8_t *hash_zero) {
        block blockR, block_tmp;
        unsigned i;

        copy_block(&blockR, ref_block);
        xor_block(&blockR, prev_block);
        copy_block(&block_tmp, &blockR);
        /* Now blockR = ref_block + prev_block and block_tmp = ref_block + prev_block */
        if (with_xor) {
            /* Saving the next block contents for XOR over: */
            xor_block(&block_tmp, next_block);
            /* Now blockR = ref_block + prev_block and
               block_tmp = ref_block + prev_block + next_block */
        }

        uint32_t the_index[2] = {0, block_index};
        memcpy(&blockR.v[14], the_index, sizeof(uint64_t));
        memcpy(&blockR.v[16], hash_zero, sizeof(uint64_t));
        memcpy(&blockR.v[17], hash_zero + 8, sizeof(uint64_t));
        memcpy(&blockR.v[18], hash_zero + 16, sizeof(uint64_t));
        memcpy(&blockR.v[19], hash_zero + 24, sizeof(uint64_t));

        /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
           (16,17,..31)... finally (112,113,...127) */
        for (i = 0; i < 8; ++i) {
            BLAKE2_ROUND_NOMSG(
                    blockR.v[16 * i], blockR.v[16 * i + 1], blockR.v[16 * i + 2],
                    blockR.v[16 * i + 3], blockR.v[16 * i + 4], blockR.v[16 * i + 5],
                    blockR.v[16 * i + 6], blockR.v[16 * i + 7], blockR.v[16 * i + 8],
                    blockR.v[16 * i + 9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
                    blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14],
                    blockR.v[16 * i + 15]);
        }

        /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
           (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
        for (i = 0; i < 8; i++) {
            BLAKE2_ROUND_NOMSG(
                    blockR.v[2 * i], blockR.v[2 * i + 1], blockR.v[2 * i + 16],
                    blockR.v[2 * i + 17], blockR.v[2 * i + 32], blockR.v[2 * i + 33],
                    blockR.v[2 * i + 48], blockR.v[2 * i + 49], blockR.v[2 * i + 64],
                    blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81],
                    blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112],
                    blockR.v[2 * i + 113]);
        }

        copy_block(next_block, &block_tmp);
        xor_block(next_block, &blockR);
    }


    void copy_block(block *dst, const block *src) {
        memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
    }

    void copy_blockS(blockS *dst, const blockS *src) {
        memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
    }

    void copy_blockS(blockS *dst, const block *src) {
        memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
    }


#define VC_GE_2005(version) (version >= 1400)

    void secure_wipe_memory(void *v, size_t n) {
#if defined(_MSC_VER) && VC_GE_2005(_MSC_VER)
        SecureZeroMemory(v, n);
#elif defined memset_s
        memset_s(v, n, 0, n);
#elif defined(__OpenBSD__)
        explicit_bzero(v, n);
#else
        static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
        memset_sec(v, 0, n);
#endif
    }

/* Memory clear flag defaults to true. */

    void clear_internal_memory(void *v, size_t n) {
        if (FLAG_clear_internal_memory && v) {
            secure_wipe_memory(v, n);
        }
    }


    void free_memory(const argon2_context *context, uint8_t *memory,
                     size_t num, size_t size) {
        size_t memory_size = num * size;
        clear_internal_memory(memory, memory_size);
        if (context->free_cbk) {
            (context->free_cbk)(memory, memory_size);
        } else {
            free(memory);
        }
    }

    argon2_context init_argon2d_param(const char *input) {

#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0
        argon2_context context;
        argon2_context *pContext = &context;

        unsigned char out[TEST_OUTLEN];

        const allocate_fptr myown_allocator = NULL;
        const deallocate_fptr myown_deallocator = NULL;

        unsigned t_cost = 1;
        unsigned m_cost = memcost; //2*1024*1024; //*1024; //+896*1024; //32768*1;

        unsigned lanes = 4;

        memset(pContext, 0, sizeof(argon2_context));
        memset(&out[0], 0, sizeof(out));
        context.out = out;
        context.outlen = TEST_OUTLEN;
        context.version = ARGON2_VERSION_NUMBER;
        context.pwd = (uint8_t *) input;
        context.pwdlen = TEST_PWDLEN;
        context.salt = (uint8_t *) input;
        context.saltlen = TEST_SALTLEN;
        context.secret = NULL;
        context.secretlen = TEST_SECRETLEN;
        context.ad = NULL;
        context.adlen = TEST_ADLEN;
        context.t_cost = t_cost;
        context.m_cost = m_cost;
        context.lanes = lanes;
        context.threads = lanes;
        context.allocate_cbk = myown_allocator;
        context.free_cbk = myown_deallocator;
        context.flags = ARGON2_DEFAULT_FLAGS;

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

        return context;
    }


    bool solver(
            uint32_t *input,
            uint32_t nonce,
            argon2_instance_t *instance,
            MerkleTree merkle_tree,
            unsigned char *merkle_root,
            uint64_t mtp_block_out[MTP_BLOCK_PROOF_SIZE * 2][128] /*[64 * 2][128]*/,
            unsigned char *mtp_proof_out,
            unsigned int *mtp_proof_size_out,
            unsigned char *hash_out) {


        if (instance != NULL) {
            //		input[19]=0x01000000;
            uint256 Y;
            //		std::string proof_blocks[L * 3];
            memset(&Y, 0, sizeof(Y));
            uint8_t zero[32] = {0};
            ablake2b_state BlakeHash;
            ablake2b_init(&BlakeHash, 32);

            uint32_t Test[4];

            for (int i = 0; i < 4; i++)
                Test[i] = ((uint32_t *) merkle_root)[i];


            ablake2b_update(&BlakeHash, (unsigned char *) &input[0], 80);
            ablake2b_update(&BlakeHash, (unsigned char *) &merkle_root[0], 16);
            ablake2b_update(&BlakeHash, &nonce, sizeof(unsigned int));
            ablake2b_final(&BlakeHash, (unsigned char *) &Y, 32);


            blockS blocks[L * 2];

            ///////////////////////////////
            bool init_blocks = false;
            bool unmatch_block = false;
            unsigned char proof_ser[1000] = {0};
            unsigned int proof_size = 0;
            for (uint8_t j = 1; j <= L; j++) {

                uint32_t ij = (((uint32_t * )(&Y))[0]) % (instance->context_ptr->m_cost);
                uint32_t except_index = (uint32_t)(instance->context_ptr->m_cost / instance->context_ptr->lanes);
                if (ij % except_index == 0 || ij % except_index == 1) {
                    init_blocks = true;
                    break;
                }

                uint32_t prev_index;
                uint32_t ref_index;
                getblockindex(ij, instance, &prev_index, &ref_index);

                for (int i = 0; i < 128; i++)
                    mtp_block_out[j * 2 - 2][i] = instance->memory[prev_index].v[i];

                for (int i = 0; i < 128; i++)
                    mtp_block_out[j * 2 - 1][i] = instance->memory[ref_index].v[i];

                block blockhash;
                uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
                mtp::copy_block(&blockhash, &instance->memory[ij]);


                store_block(&blockhash_bytes, &blockhash);

                ablake2b_state BlakeHash2;
                ablake2b_init(&BlakeHash2, 32);
                ablake2b_update(&BlakeHash2, &Y, sizeof(uint256));
                ablake2b_update(&BlakeHash2, blockhash_bytes, ARGON2_BLOCK_SIZE);
                ablake2b_final(&BlakeHash2, (unsigned char *) &Y, 32);
                ////////////////////////////////////////////////////////////////
                // current block

                unsigned char curr[32] = {0};
                block blockhash_curr;
                uint8_t blockhash_curr_bytes[ARGON2_BLOCK_SIZE];
                mtp::copy_block(&blockhash_curr, &instance->memory[ij]);
                store_block(&blockhash_curr_bytes, &blockhash_curr);
                ablake2b_state state_curr;
                ablake2b_init(&state_curr, MERKLE_TREE_ELEMENT_SIZE_B);
                ablake2b4rounds_update(&state_curr, blockhash_curr_bytes, ARGON2_BLOCK_SIZE);
                uint8_t digest_curr[MERKLE_TREE_ELEMENT_SIZE_B];
                ablake2b4rounds_final(&state_curr, digest_curr, sizeof(digest_curr));
                MerkleTree::Buffer hash_curr = MerkleTree::Buffer(digest_curr, digest_curr + sizeof(digest_curr));
                mtp::clear_internal_memory(blockhash_curr.v, ARGON2_BLOCK_SIZE);
                mtp::clear_internal_memory(blockhash_curr_bytes, ARGON2_BLOCK_SIZE);


                std::deque <std::vector<uint8_t>> zProofMTP = merkle_tree.getProofOrdered(hash_curr, ij + 1);

                mtp_proof_out[(j * 3 - 3) * 353] = (unsigned char) (zProofMTP.size());
                proof_size += zProofMTP.size() * 16 + 1;

                int k1 = 0;
                for (const std::vector <uint8_t> &mtpData : zProofMTP) {
                    std::copy(mtpData.begin(), mtpData.end(),
                              mtp_proof_out + ((j * 3 - 3) * 353 + 1 + k1 * mtpData.size()));
                    k1++;
                }

                //prev proof
                unsigned char prev[32] = {0};
                block blockhash_prev;
                uint8_t blockhash_prev_bytes[ARGON2_BLOCK_SIZE];
                mtp::copy_block(&blockhash_prev, &instance->memory[prev_index]);
                store_block(&blockhash_prev_bytes, &blockhash_prev);
                ablake2b_state state_prev;
                ablake2b_init(&state_prev, MERKLE_TREE_ELEMENT_SIZE_B);
                ablake2b4rounds_update(&state_prev, blockhash_prev_bytes, ARGON2_BLOCK_SIZE);
                uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];


                ablake2b4rounds_final(&state_prev, digest_prev, sizeof(digest_prev));


                MerkleTree::Buffer hash_prev = MerkleTree::Buffer(digest_prev, digest_prev + sizeof(digest_prev));
                mtp::clear_internal_memory(blockhash_prev.v, ARGON2_BLOCK_SIZE);
                mtp::clear_internal_memory(blockhash_prev_bytes, ARGON2_BLOCK_SIZE);

                std::deque <std::vector<uint8_t>> zProofMTP2 = merkle_tree.getProofOrdered(hash_prev, prev_index + 1);

                mtp_proof_out[(j * 3 - 2) * 353] = (unsigned char) (zProofMTP2.size());
                proof_size += zProofMTP2.size() * 16 + 1;

                int k2 = 0;
                for (const std::vector <uint8_t> &mtpData : zProofMTP2) {
                    std::copy(mtpData.begin(), mtpData.end(),
                              mtp_proof_out + ((j * 3 - 2) * 353 + 1 + k2 * mtpData.size()));
                    k2++;
                }


                //ref proof
                unsigned char ref[32] = {0};
                block blockhash_ref;
                uint8_t blockhash_ref_bytes[ARGON2_BLOCK_SIZE];
                mtp::copy_block(&blockhash_ref, &instance->memory[ref_index]);
                store_block(&blockhash_ref_bytes, &blockhash_ref);
                ablake2b_state state_ref;
                ablake2b_init(&state_ref, MERKLE_TREE_ELEMENT_SIZE_B);
                ablake2b4rounds_update(&state_ref, blockhash_ref_bytes, ARGON2_BLOCK_SIZE);
                uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
                ablake2b4rounds_final(&state_ref, digest_ref, sizeof(digest_ref));
                MerkleTree::Buffer hash_ref = MerkleTree::Buffer(digest_ref, digest_ref + sizeof(digest_ref));
                mtp::clear_internal_memory(blockhash_ref.v, ARGON2_BLOCK_SIZE);
                mtp::clear_internal_memory(blockhash_ref_bytes, ARGON2_BLOCK_SIZE);

                std::deque <std::vector<uint8_t>> zProofMTP3 = merkle_tree.getProofOrdered(hash_ref, ref_index + 1);

                mtp_proof_out[(j * 3 - 1) * 353] = (unsigned char) (zProofMTP3.size());
                proof_size += zProofMTP3.size() * 16 + 1;

                int k3 = 0;
                for (const std::vector <uint8_t> &mtpData : zProofMTP3) {
                    std::copy(mtpData.begin(), mtpData.end(),
                              mtp_proof_out + ((j * 3 - 1) * 353 + 1 + k3 * mtpData.size()));
                    k3++;
                }

            }

            if (init_blocks)
                return false;

            char hex_tmp[64];

            *mtp_proof_size_out = proof_size;

            for (int i = 0; i < 32; i++) {
                hash_out[i] = (((unsigned char *) (&Y))[i]);
            }

            // Found a solution
            return true;
        }

        return false;
    }


    bool solver_fast(
            uint32_t nonce,
            argon2_instance_t *instance,
            unsigned char *merkle_root,
            uint32_t *input,
            uint256 target,
            uint256 *hash_out) {

        if (instance != NULL) {
            uint256 Y;
            ablake2b_state blake_hash;
            ablake2b_init(&blake_hash, 32);
            ablake2b_update(&blake_hash, (unsigned char *) &input[0], 80);
            ablake2b_update(&blake_hash, (unsigned char *) &merkle_root[0], 16);
            ablake2b_update(&blake_hash, &nonce, sizeof(unsigned int));
            ablake2b_final(&blake_hash, (unsigned char *) &Y, 32);

            bool init_blocks = false;
            bool unmatch_block = false;

            for (uint8_t j = 1; j <= L; j++) {

                uint32_t ij = (((uint32_t *) (&Y))[0]) % (instance->context_ptr->m_cost);
                uint32_t except_index = (uint32_t) (instance->context_ptr->m_cost / instance->context_ptr->lanes);
                if (ij % except_index == 0 || ij % except_index == 1) {
                    init_blocks = true;
                    break;
                }

                ablake2b_init(&blake_hash, 32);
                ablake2b_update(&blake_hash, &Y, sizeof(uint256));
                ablake2b_update(&blake_hash, &instance->memory[ij].v, ARGON2_BLOCK_SIZE);
                ablake2b_final(&blake_hash, (unsigned char *) &Y, 32);
            }

            if (hash_out)
                *hash_out = Y;

            if (init_blocks)
                return false;

            if (Y <= target)
                return true;
        }
        return false;
    }


    bool verify(const char *input,
                    uint32_t nonce,
                    const uint8_t hash_root_mtp[16],
                    const uint64_t block_mtp[L * 2][128],
                    const std::deque<std::vector<uint8_t>> proof_mtp[L * 3],
                    uint256 *hash_out) {

        MerkleTree::Buffer const root(&hash_root_mtp[0], &hash_root_mtp[16]);
        block blocks[L * 2];

        for (int i = 0; i < (L * 2); ++i) {
            memcpy(blocks[i].v, block_mtp[i],
                   sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        }

        argon2_context context_verify = init_argon2d_param(input);

        uint32_t memory_blocks = context_verify.m_cost;
        if (memory_blocks < (2 * ARGON2_SYNC_POINTS * context_verify.lanes)) {
            memory_blocks = 2 * ARGON2_SYNC_POINTS * context_verify.lanes;
        }
        uint32_t segment_length = memory_blocks / (context_verify.lanes * ARGON2_SYNC_POINTS);

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
        memset(&y[0], 0, sizeof(y));

        ablake2b_state state_y0;
        ablake2b_init(&state_y0, 32); // 256 bit
        ablake2b_update(&state_y0, input, 80);
        ablake2b_update(&state_y0, hash_root_mtp, MERKLE_TREE_ELEMENT_SIZE_B);
        ablake2b_update(&state_y0, &nonce, sizeof(unsigned int));
        ablake2b_final(&state_y0, &y[0], sizeof(uint256));

        // get hash_zero
        uint8_t h0[ARGON2_PREHASH_SEED_LENGTH];
        initial_hash(h0, &context_verify, instance.type);

        // step 8
        for (uint32_t j = 1; j <= L; ++j) {

            uint32_t ij = (((uint32_t *) (&y[j-1]))[0]) % M_COST;

            // retrieve x[ij-1] and x[phi(i)] from proof
            block prev_block, ref_block, t_prev_block, t_ref_block;
            memcpy(t_prev_block.v, block_mtp[(j * 2) - 2],
                   sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
            memcpy(t_ref_block.v, block_mtp[j * 2 - 1],
                   sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
            mtp::copy_block(&prev_block, &t_prev_block);
            mtp::copy_block(&ref_block, &t_ref_block);
            mtp::clear_internal_memory(t_prev_block.v, ARGON2_BLOCK_SIZE);
            mtp::clear_internal_memory(t_ref_block.v, ARGON2_BLOCK_SIZE);

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

            uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(prev_block, digest_prev);
            MerkleTree::Buffer hash_prev(digest_prev,
                                         digest_prev + sizeof(digest_prev));
            if (!MerkleTree::checkProofOrdered((MerkleTree::Elements)proof_mtp[(j * 3) - 2],
                                               root, hash_prev, ij_prev + 1)) {
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

            argon2_position_t position{0, lane, (uint8_t) slice, pos_index};
            uint32_t ref_index = index_beta(&instance, &position, pseudo_rand,
                                            ref_lane == position.lane);

            uint32_t computed_ref_block = (lane_length * ref_lane) + ref_index;

            uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
            compute_blake2b(ref_block, digest_ref);
            MerkleTree::Buffer hash_ref(digest_ref, digest_ref + sizeof(digest_ref));
            if (!MerkleTree::checkProofOrdered((MerkleTree::Elements)proof_mtp[(j * 3) - 1],
                                               root, hash_ref, computed_ref_block + 1)) {
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

            if (!MerkleTree::checkProofOrdered((MerkleTree::Elements)proof_mtp[(j * 3) - 3], root,
                                                hash_ij, ij + 1)) {
                return false;
            }

            // compute y(j)
            block blockhash;
            mtp::copy_block(&blockhash, &block_ij);
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            StoreBlock(&blockhash_bytes, &blockhash);
            ablake2b_state ctx_yj;
            ablake2b_init(&ctx_yj, 32);
            ablake2b_update(&ctx_yj, &y[j - 1], 32);
            ablake2b_update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
            ablake2b_final(&ctx_yj, &y[j], 32);
            mtp::clear_internal_memory(block_ij.v, ARGON2_BLOCK_SIZE);
            mtp::clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            mtp::clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
        }

        // step 9
        for (int i = 0; i < (L * 2); ++i) {
            mtp::clear_internal_memory(blocks[i].v, ARGON2_BLOCK_SIZE);
        }

        if (hash_out)
            *hash_out = y[L];

        return true;
    }

    bool verify_fast(const char *input,
                uint32_t nonce,
                const uint8_t hash_root_mtp[16],
                const uint64_t block_mtp[L * 2][128],
                uint256 *hash_out) {

        block blocks[L * 2];
        for (int i = 0; i < (L * 2); ++i) {
            memcpy(blocks[i].v, block_mtp[i],
                   sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
        }

        argon2_context context_verify = init_argon2d_param(input);

        // step 7
        uint256 y[L + 1];
        memset(&y[0], 0, sizeof(y));

        ablake2b_state state_y0;
        ablake2b_init(&state_y0, 32); // 256 bit
        ablake2b_update(&state_y0, input, 80);
        ablake2b_update(&state_y0, hash_root_mtp, MERKLE_TREE_ELEMENT_SIZE_B);
        ablake2b_update(&state_y0, &nonce, sizeof(unsigned int));
        ablake2b_final(&state_y0, &y[0], sizeof(uint256));

        // get hash_zero
        uint8_t h0[ARGON2_PREHASH_SEED_LENGTH];
        initial_hash(h0, &context_verify, Argon2_d);

        // step 8
        for (uint32_t j = 1; j <= L; ++j) {

            uint32_t ij = (((uint32_t *) (&y[j-1]))[0]) % M_COST;

            // retrieve x[ij-1] and x[phi(i)] from proof
            block prev_block, t_prev_block;
            memcpy(t_prev_block.v, block_mtp[(j * 2) - 2],
                   sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
            mtp::copy_block(&prev_block, &t_prev_block);
            mtp::clear_internal_memory(t_prev_block.v, ARGON2_BLOCK_SIZE);

            //prev_index
            //compute
            uint32_t memory_blocks_2 = M_COST;
            if (memory_blocks_2 < (2 * ARGON2_SYNC_POINTS * LANES)) {
                memory_blocks_2 = 2 * ARGON2_SYNC_POINTS * LANES;
            }

            uint32_t segment_length_2 = memory_blocks_2 / (LANES * ARGON2_SYNC_POINTS);
            uint32_t lane_length = segment_length_2 * ARGON2_SYNC_POINTS;

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

            argon2_position_t position{0, lane, (uint8_t) slice, pos_index};
            uint32_t ref_index = index_beta(&instance, &position, pseudo_rand,
                                            ref_lane == position.lane);

            uint32_t computed_ref_block = (lane_length * ref_lane) + ref_index;

            // compute x[ij]
            block block_ij;
            fill_block_mtp(&blocks[(j * 2) - 2], &blocks[(j * 2) - 1],
                           &block_ij, 0, computed_ref_block, h0);

            // compute y(j)
            block blockhash;
            mtp::copy_block(&blockhash, &block_ij);
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            StoreBlock(&blockhash_bytes, &blockhash);
            ablake2b_state ctx_yj;
            ablake2b_init(&ctx_yj, 32);
            ablake2b_update(&ctx_yj, &y[j - 1], 32);
            ablake2b_update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
            ablake2b_final(&ctx_yj, &y[j], 32);
            mtp::clear_internal_memory(block_ij.v, ARGON2_BLOCK_SIZE);
            mtp::clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            mtp::clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
        }

        // step 9
        if (FLAG_clear_internal_memory) {
            for (int i = 0; i < (L * 2); ++i) {
                mtp::clear_internal_memory(blocks[i].v, ARGON2_BLOCK_SIZE);
            }
        }

        if (hash_out)
            *hash_out = y[L];

        return true;
    }


    MerkleTree::Elements init(argon2_instance_t *instance) {

        MerkleTree::Elements elements;
        if (instance != NULL) {

            for (long int i = 0; i < instance->memory_blocks; ++i) {
                uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
                compute_blake2b(instance->memory[i], digest);
                elements.emplace_back(digest, digest + sizeof(digest));
            }

            return elements;
        }
    }
}