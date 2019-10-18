const mtp = require('bindings')('hashermtp.node');

const MTP_L = 64;
const ZCOIN_INPUT_SIZE = 80;
const NONCE_SIZE = 4;
const TARGET_SIZE = 32;
const MTP_HASH_ROOT_SIZE = 16;
const MTP_BLOCK_SIZE = 8 * MTP_L * 2 * 128;
const MAX_PROOF_SIZE = MTP_L * 3 * 353;
const MTP_HASH_VALUE_SIZE = 32;
const HASH_OUTPUT_BUFFER = Buffer.alloc(4 + NONCE_SIZE + MTP_HASH_VALUE_SIZE + MTP_HASH_ROOT_SIZE + MTP_BLOCK_SIZE + MAX_PROOF_SIZE);

/**
 * Solve the hash problem. This function will try different nonce until it finds one such that the
 * computed hash is less than the `target` difficulty.
 *
 * @param  mtpInput   {Buffer}  80-byte header data to hash
 * @param  target     {Buffer}  32-byte target
 * @param  nonceStart {Buffer}  4-byte nonce to start with.
 * @param  nonceEnd   {Buffer}  4-byte nonce to stop at.
 *
 * @returns {boolean|object} False if a nonce was not found, otherwise an object containing nonce and MTP proofs
 * in Buffers.
 * @returns {{
 *     nonce: {Buffer},
 *     hashValue: {Buffer},
 *     hashRoot: {Buffer},
 *     block: {Buffer},
 *     proof: {Buffer}
 * }}
 */
module.exports.hash = hash;

/**
 * This function will hash the MTP input using the supplied nonce value.
 *
 * @param  mtpInput   {Buffer}  80-byte header data to hash
 * @param  nonce      {Buffer}  4-byte nonce.
 *
 * @returns {boolean|object} False if hashing failed, otherwise an object containing nonce and MTP proofs
 * in Buffers.
 * @returns {{
 *     nonce: {Buffer},
 *     hashValue: {Buffer},
 *     hashRoot: {Buffer},
 *     block: {Buffer},
 *     proof: {Buffer}
 * }}
 */
module.exports.hashOne = hashOne;

/**
 * Verify the given MTP proofs are valid and get hash result.
 *
 * @param mtpHeader    {Buffer}  80-byte header that was hashed.
 * @param nonce        {Buffer}  4-byte nonce to check.
 * @param hashRoot     {Buffer}  16-byte MTP hash root used for verification.
 * @param block        {Buffer}  MTP block data used for verification.
 * @param proof        {Buffer}  NTP proof data used for verification.
 * @param hashValueOut {Buffer}  A 32-byte buffer to put the hash result into.
 *
 * @returns {boolean} True if verification is successful, otherwise false.
 */
module.exports.verify = verify;

/**
 * Verify the given MTP proofs are valid and get hash result. Use to quickly find invalid proofs. In some cases may
 * pass an invalid proof.
 *
 * "verifyFast" is already used by "verify" before doing a full verify of the proofs.
 *
 * @param mtpHeader    {Buffer}  80-byte header that was hashed.
 * @param nonce        {Buffer}  4-byte nonce to check.
 * @param hashRoot     {Buffer}  16-byte MTP hash root used for verification.
 * @param block        {Buffer}  MTP block data used for verification.
 * @param proof        {Buffer}  NTP proof data used for verification.
 * @param hashValueOut {Buffer}  A 32-byte buffer to put the hash result into.
 *
 * @returns {boolean} True if verification is successful, otherwise false.
 */
module.exports.verifyFast = verifyFast;


function hash(mtpInput, target, nonceStart, nonceEnd) {

    _expectBuffer(mtpInput, 'mtpInput', ZCOIN_INPUT_SIZE);
    _expectBuffer(target, 'target', TARGET_SIZE);
    _expectBuffer(nonceStart, 'nonceStart', NONCE_SIZE);
    _expectBuffer(nonceEnd, 'nonceEnd', NONCE_SIZE);

    const isSuccess = mtp.hash(mtpInput, target, nonceStart, nonceEnd, HASH_OUTPUT_BUFFER);
    if (!isSuccess)
        return false;

    const size = HASH_OUTPUT_BUFFER.readUInt32LE(0);
    const proofSize = size - NONCE_SIZE - MTP_HASH_VALUE_SIZE - MTP_HASH_ROOT_SIZE - MTP_BLOCK_SIZE;
    const buffers = {
        nonce: Buffer.alloc(NONCE_SIZE),
        hashValue: Buffer.alloc(MTP_HASH_VALUE_SIZE),
        hashRoot: Buffer.alloc(MTP_HASH_ROOT_SIZE),
        block: Buffer.alloc(MTP_BLOCK_SIZE),
        proof: Buffer.alloc(proofSize)
    };

    let pos = 4/*output size*/;

    HASH_OUTPUT_BUFFER.copy(buffers.nonce, 0, pos);
    pos += NONCE_SIZE;

    HASH_OUTPUT_BUFFER.copy(buffers.hashValue, 0, pos);
    pos += MTP_HASH_VALUE_SIZE;

    HASH_OUTPUT_BUFFER.copy(buffers.hashRoot, 0, pos);
    pos += MTP_HASH_ROOT_SIZE;

    HASH_OUTPUT_BUFFER.copy(buffers.block, 0, pos);
    pos += MTP_BLOCK_SIZE;

    HASH_OUTPUT_BUFFER.copy(buffers.proof, 0, pos);

    return buffers;
}


function hashOne(mtpInput, nonce) {

    _expectBuffer(mtpInput, 'mtpInput', ZCOIN_INPUT_SIZE);
    _expectBuffer(nonce, 'nonce', NONCE_SIZE);

    const isSuccess = mtp.hash_one(mtpInput, nonce, HASH_OUTPUT_BUFFER);
    if (!isSuccess)
        return false;

    const size = HASH_OUTPUT_BUFFER.readUInt32LE(0);
    const proofSize = size - NONCE_SIZE - MTP_HASH_VALUE_SIZE - MTP_HASH_ROOT_SIZE - MTP_BLOCK_SIZE;
    const buffers = {
        nonce: Buffer.alloc(NONCE_SIZE),
        hashValue: Buffer.alloc(MTP_HASH_VALUE_SIZE),
        hashRoot: Buffer.alloc(MTP_HASH_ROOT_SIZE),
        block: Buffer.alloc(MTP_BLOCK_SIZE),
        proof: Buffer.alloc(proofSize)
    };

    let pos = 4/*output size*/;

    HASH_OUTPUT_BUFFER.copy(buffers.nonce, 0, pos);
    pos += NONCE_SIZE;

    HASH_OUTPUT_BUFFER.copy(buffers.hashValue, 0, pos);
    pos += MTP_HASH_VALUE_SIZE;

    HASH_OUTPUT_BUFFER.copy(buffers.hashRoot, 0, pos);
    pos += MTP_HASH_ROOT_SIZE;

    HASH_OUTPUT_BUFFER.copy(buffers.block, 0, pos);
    pos += MTP_BLOCK_SIZE;

    HASH_OUTPUT_BUFFER.copy(buffers.proof, 0, pos);

    return buffers;
}


function verify(mtpHeader, nonce, hashRoot, block, proof, hashValueOut) {

    _expectBuffer(mtpHeader, 'mtpHeader', ZCOIN_INPUT_SIZE);
    _expectBuffer(nonce, 'nonce', NONCE_SIZE);
    _expectBuffer(hashRoot, 'hashRoot', MTP_HASH_ROOT_SIZE);
    _expectBuffer(block, 'block', MTP_BLOCK_SIZE);
    _expectBuffer(proof, 'proof');
    _expectBuffer(hashValueOut, 'hashValueOut', MTP_HASH_VALUE_SIZE);

    return mtp.verify(mtpHeader, nonce, hashRoot, block, proof, hashValueOut);
}


function verifyFast(mtpHeader, nonce, hashRoot, block, proof, hashValueOut) {

    _expectBuffer(mtpHeader, 'mtpHeader', ZCOIN_INPUT_SIZE);
    _expectBuffer(nonce, 'nonce', NONCE_SIZE);
    _expectBuffer(hashRoot, 'hashRoot', MTP_HASH_ROOT_SIZE);
    _expectBuffer(block, 'block', MTP_BLOCK_SIZE);
    _expectBuffer(proof, 'proof');
    _expectBuffer(hashValueOut, 'hashValueOut', MTP_HASH_VALUE_SIZE);

    return mtp.verify_fast(mtpHeader, nonce, hashRoot, block, proof, hashValueOut);
}


function _expectBuffer(buffer, name, size) {
    if (!Buffer.isBuffer(buffer))
        throw new Error(`"${name}" is expected to be a Buffer. Got ${(typeof buffer)} instead.`);

    if (size && buffer.length !== size)
        throw new Error(`"${name}" is expected to be exactly ${size} bytes. Got ${buffer.length} instead.`);
}