{
    "targets": [
        {
            "target_name": "hashermtp",
            "sources": [
                "src/crypto/ripemd160.cpp",
                "src/MerkleTreeProof/blake2/blake2b.c",
                "src/MerkleTreeProof/crypto/sha256.cpp",
                "src/MerkleTreeProof/arith_uint256.cpp",
                "src/MerkleTreeProof/core.c",
                "src/MerkleTreeProof/merkle-tree.cpp",
                "src/MerkleTreeProof/merkle-tree.hpp",
                "src/MerkleTreeProof/mtp-core.cpp",
                "src/MerkleTreeProof/mtp-hash.cpp",
                "src/MerkleTreeProof/mtp-verify.cpp",
                "src/MerkleTreeProof/ref.c",
                "src/MerkleTreeProof/thread.c",
                "src/support/cleanse.cpp",
                "src/logging.cpp",
                "src/uint256.cpp",
                "src/utilstrencodings.cpp",
                "hashermtp.cc"
            ],
            "include_dirs": [
                "src",
                "<!(node -e \"require('nan')\")"
            ],
            "cflags_cc": [
                "-std=c++0x"
            ]
        }
    ]
}
