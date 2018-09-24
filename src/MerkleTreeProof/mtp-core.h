#ifndef MTP_CORE_H_
#define MTP_CORE_H_

#include "mtp.h"
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

#include "merkle-tree.hpp"

namespace mtp
{
    void StoreBlock(void *output, const block *src);

    int Argon2CtxMtp(argon2_context *context, argon2_type type,
                     argon2_instance_t *instance);

    uint32_t IndexBeta(const argon2_instance_t *instance,
                       const argon2_position_t *position, uint32_t pseudo_rand,
                       int same_lane);

    void GetBlockIndex(uint32_t ij, argon2_instance_t *instance,
                       uint32_t *out_ij_prev, uint32_t *out_computed_ref_block);

    void compute_blake2b(const block &input,
                         uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B]);

    struct TargetHelper
    {
        bool m_negative;
        bool m_overflow;
        arith_uint256 m_target;

        TargetHelper(uint32_t target)
        {
            m_target.SetCompact(target, &m_negative, &m_overflow);
        }
    };
}

#endif
