{
    "targets": [
        {
            "target_name": "hashermtp",
            "sources": [
                "src/argon2ref/argon2.c",
                "src/argon2ref/blake2ba.c",
                "src/argon2ref/core.c",
                "src/argon2ref/encoding.c",
                "src/argon2ref/ref.c",
                "src/argon2ref/thread.c",
                "src/merkletree/merkle-tree.cpp",
                "src/merkletree/mtp.cpp",
                "src/sha3/sph_blake.c",
                "hashermtp.cc"
            ],
            "include_dirs": [
                ".",
                "src",
                "<!(node -e \"require('nan')\")"
            ],
            "cflags_cc": [
                "-std=c++0x"
            ]
        }
    ]
}