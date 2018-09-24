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
//#include "primitives/block.h"
#include "streams.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/numeric/conversion/cast.hpp>

using boost::numeric_cast;
using boost::numeric::bad_numeric_cast;
using boost::numeric::positive_overflow;
using boost::numeric::negative_overflow;

extern int validate_inputs(const argon2_context *context);
extern void clear_internal_memory(void *v, size_t n);

#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0

namespace mtp
{
    void StoreBlock(void *output, const block *src)
    {
        for (unsigned i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
            store64(static_cast<uint8_t*>(output)
                    + (i * sizeof(src->v[i])), src->v[i]);
        }
    }

    int Argon2CtxMtp(argon2_context *context, argon2_type type,
                     argon2_instance_t *instance)
    {
        int result = validate_inputs(context);
        if (result != ARGON2_OK) {
            return result;
        }
        if ((type != Argon2_d) && (type != Argon2_i) && (type != Argon2_id)) {
            return ARGON2_INCORRECT_TYPE;
        }
        result = initialize(instance, context);
        if (result != ARGON2_OK) {
            return result;
        }
        result = fill_memory_blocks_mtp(instance, context);
        if (result != ARGON2_OK) {
            return result;
        }
        return ARGON2_OK;
    }

    uint32_t IndexBeta(const argon2_instance_t *instance,
                       const argon2_position_t *position, uint32_t pseudo_rand,
                       int same_lane)
    {
        /*
         * Pass 0:
         *      This lane : all already finished segments plus already constructed
         * blocks in this segment
         *      Other lanes : all already finished segments
         * Pass 1+:
         *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
         * blocks in this segment
         *      Other lanes : (SYNC_POINTS - 1) last segments
         */
        uint32_t reference_area_size;
        if (position->pass == 0) {
            /* First pass */
            if (position->slice == 0) {
                /* First slice */
                reference_area_size = position->index - 1; // all but the previous
            } else {
                if (same_lane) {
                    /* The same lane => add current segment */
                    reference_area_size =
                            (position->slice * instance->segment_length)
                            + position->index - 1;
                } else {
                    reference_area_size =
                            (position->slice * instance->segment_length)
                            + ((position->index == 0) ? -1 : 0);
                }
            }
        } else {
            /* Second pass */
            if (same_lane) {
                reference_area_size = instance->lane_length
                                      - instance->segment_length + position->index - 1;
            } else {
                reference_area_size = instance->lane_length
                                      - instance->segment_length + ((position->index == 0) ? -1 : 0);
            }
        }

        /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
         * relative position */
        uint64_t relative_position = pseudo_rand;
        relative_position = (relative_position * relative_position) >> 32;
        relative_position = reference_area_size - 1
                            - ((reference_area_size * relative_position) >> 32);

        /* 1.2.5 Computing starting position */
        uint32_t start_position = 0;
        if (position->pass != 0) {
            start_position = (position->slice == (ARGON2_SYNC_POINTS - 1))
                             ? 0
                             : (position->slice + 1) * instance->segment_length;
        }

        /* 1.2.6. Computing absolute position */
        uint64_t absolute_position = (static_cast<uint64_t>(start_position)
                                      + relative_position) % static_cast<uint64_t>(instance->lane_length);
        return static_cast<uint32_t>(absolute_position);
    }

    void GetBlockIndex(uint32_t ij, argon2_instance_t *instance,
                       uint32_t *out_ij_prev, uint32_t *out_computed_ref_block)
    {
        uint32_t ij_prev = 0;
        if ((ij % instance->lane_length) == 0) {
            ij_prev = ij + instance->lane_length - 1;
        } else {
            ij_prev = ij - 1;
        }
        if ((ij % instance->lane_length) == 1) {
            ij_prev = ij - 1;
        }

        uint64_t prev_block_opening = instance->memory[ij_prev].v[0];
        uint32_t ref_lane = static_cast<uint32_t>((prev_block_opening >> 32)
                                                  % static_cast<uint64_t>(instance->lanes));
        uint32_t pseudo_rand = static_cast<uint32_t>(prev_block_opening & 0xFFFFFFFF);
        uint32_t lane = ij / instance->lane_length;
        uint32_t slice = (ij - (lane * instance->lane_length))
                         / instance->segment_length;
        uint32_t pos_index = ij - (lane * instance->lane_length)
                             - (slice * instance->segment_length);
        if (slice == 0) {
            ref_lane = lane;
        }

        argon2_position_t position { 0, lane , (uint8_t)slice, pos_index };
        uint32_t ref_index = IndexBeta(instance, &position, pseudo_rand,
                                       ref_lane == position.lane);
        uint32_t computed_ref_block = (instance->lane_length * ref_lane) + ref_index;
        *out_ij_prev = ij_prev;
        *out_computed_ref_block = computed_ref_block;
    }

/** Compute a BLAKE2B hash on a block
 *
 * \param input  [in]  Block to compute the hash on
 * \param digest [out] Computed hash
 */
    void compute_blake2b(const block& input,
                         uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B])
    {
        block tmp_block;
        copy_block(&tmp_block, &input);
        uint8_t tmp_block_bytes[ARGON2_BLOCK_SIZE];
        StoreBlock(&tmp_block_bytes, &tmp_block);

        blake2b_state state;
        blake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
        blake2b_4r_update(&state, tmp_block_bytes, ARGON2_BLOCK_SIZE);

        blake2b_4r_final(&state, digest, MERKLE_TREE_ELEMENT_SIZE_B);
        clear_internal_memory(tmp_block.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(tmp_block_bytes, ARGON2_BLOCK_SIZE);
    }
}

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN
