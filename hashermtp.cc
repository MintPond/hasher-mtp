#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <iostream>
#include "nan.h"
#include "MerkleTreeProof/mtp.h"
#include "logging.h"

#include "MerkleTreeProof/arith_uint256.h"

using namespace node;
using namespace v8;

namespace {

    const int8_t L = mtp::L;
    const int VEC_SIZE = 16;
    const int NONCE_SIZE = sizeof(uint32_t);
    const int HASH_ROOT_SIZE = sizeof(uint8_t) * 16;
    const int BLOCK_SIZE = sizeof(uint64_t) * L * 2 * 128;
    const int HASH_VALUE_SIZE = 32;

    unsigned int GetProofSize(std::deque<std::vector<uint8_t>> proof[L * 3]) {

        unsigned int size = L*3;

        for (int i = 0; i < L*3; ++i) {
            uint8_t deq_size = (uint8_t)proof[i].size();
            size += deq_size * VEC_SIZE;
        }
        return size;
    }
}

NAN_METHOD(hash) {

        if (info.Length() < 5) {
            return THROW_ERROR_EXCEPTION("hasher-mtp.hash - 5 arguments expected.");
        }

        char* header_ptr = (char*)Buffer::Data(info[0]->ToObject());
        char* target_ptr = (char*)Buffer::Data(info[1]->ToObject());
        char* nonce_start_ptr = (char*)Buffer::Data(info[2]->ToObject());
        char* nonce_end_ptr = (char*)Buffer::Data(info[3]->ToObject());
        char* output_ptr = (char*)Buffer::Data(info[4]->ToObject());

        uint256 target;
        uint256 hash_value;

        // target
        std::memcpy(target.begin(), target_ptr, target.size());

        // proofs
        uint8_t hash_root[16];
        uint64_t block[L*2][128];
        std::deque<std::vector<uint8_t>> proof[L * 3];

        uint32_t bits = UintToArith256(target).GetCompact();
        uint32_t nonce = *(uint32_t*)nonce_start_ptr;
        uint32_t nonce_end = *(uint32_t*)nonce_end_ptr;

        bool isValid = mtp::hash(header_ptr, bits, nonce, nonce_end, hash_root, block, proof, hash_value);

        if (!isValid) {
            info.GetReturnValue().Set(Nan::False());
        }
        else {

            info.GetReturnValue().Set(Nan::True());

            char* output_pos = output_ptr;

            // output data size
            uint32_t result_size =
                    NONCE_SIZE +
                    HASH_VALUE_SIZE +
                    HASH_ROOT_SIZE +
                    BLOCK_SIZE +
                    GetProofSize(proof);

            std::memcpy(output_pos, &result_size, sizeof(uint32_t));
            output_pos += sizeof(uint32_t);

            // nonce
            std::memcpy(output_pos, &nonce, NONCE_SIZE);
            output_pos += NONCE_SIZE;

            // hash_value
            std::memcpy(output_pos, (const char*)hash_value.begin(), HASH_VALUE_SIZE);
            output_pos += HASH_VALUE_SIZE;

            // hash_root_mtp
            std::memcpy(output_pos, &hash_root, HASH_ROOT_SIZE);
            output_pos += HASH_ROOT_SIZE;

            // block_mtp
            std::memcpy(output_pos, &block, BLOCK_SIZE);
            output_pos += BLOCK_SIZE;

            // proof_mtp
            for (int i = 0; i < L*3; ++i) {
                std::deque <std::vector<uint8_t>> deq = proof[i];

                uint8_t deq_size = (uint8_t)deq.size();
                std::memcpy(output_pos, &deq_size, sizeof(uint8_t));
                output_pos += sizeof(uint8_t);

                for (int j = 0; j < deq_size; ++j) {
                    std::vector <uint8_t> vec = deq.at(j);
                    std::memcpy(output_pos, (const char *) vec.data(), VEC_SIZE);
                    output_pos += VEC_SIZE;
                }
            }
        }
}

NAN_METHOD(verify) {

        if (info.Length() < 6) {
            return THROW_ERROR_EXCEPTION("hasher-mtp.verify - 6 arguments expected.");
        }

        char* input_ptr = (char*)Buffer::Data(info[0]->ToObject());
        char* nonce_ptr = (char*)Buffer::Data(info[1]->ToObject());
        char* hash_root_ptr = (char*)Buffer::Data(info[2]->ToObject());
        char* block_ptr = (char*)Buffer::Data(info[3]->ToObject());
        char* proof_ptr = (char*)Buffer::Data(info[4]->ToObject());
        char* hash_value_out_ptr = (char*)Buffer::Data(info[5]->ToObject());

        // hash root
        uint8_t hash_root[16];
        std::memcpy(&hash_root, hash_root_ptr, HASH_ROOT_SIZE);

        // block
        uint64_t block[L*2][128];
        std::memcpy(&block, block_ptr, BLOCK_SIZE);

        // proof
        std::deque<std::vector<uint8_t>> proof[L * 3];
        char* proof_pos = proof_ptr;

        for (int i=0; i < L*3; ++i) {

            uint8_t deq_size;
            std::memcpy(&deq_size, proof_pos, sizeof(uint8_t));
            proof_pos += sizeof(uint8_t);

            std::deque<std::vector<uint8_t>> deq;

            for (int j=0; j < deq_size; ++j) {
                std::vector<uint8_t> vec;
                for (int k=0; k < VEC_SIZE; ++k) {
                    uint8_t val;
                    std::memcpy(&val, proof_pos, sizeof(uint8_t));
                    proof_pos += sizeof(uint8_t);
                    vec.push_back(val);
                }
                deq.push_back(vec);
            }
            proof[i] = deq;
        }

        uint32_t nonce = *(uint32_t*)nonce_ptr;
        uint256 hash_value;

        bool isValid = mtp::verify(input_ptr, nonce, hash_root, block, proof, &hash_value);

        if (isValid) {
            std::memcpy(hash_value_out_ptr, hash_value.begin(), hash_value.size());
            info.GetReturnValue().Set(Nan::True());
        }
        else {
            info.GetReturnValue().Set(Nan::False());
        }
}

NAN_MODULE_INIT(init) {
        Nan::Set(target, Nan::New("hash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(hash)).ToLocalChecked());
        Nan::Set(target, Nan::New("verify").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(verify)).ToLocalChecked());
}

NODE_MODULE(hashermtp, init)
