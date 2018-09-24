node-hasher-mtp
===============

This is a Node module for simple hashing and verifying inputs using the
MTP (Merkle Tree Proof) proof-of-work algorithm as implemented by [Zcoin](https://zcoin.io).

This module has been developed and tested on [Node v8.12](https://nodejs.org/) and [Ubuntu 16.04](http://releases.ubuntu.com/16.04/)

## Usage ##
__Hash__
```js
const mtp = require('hasher-mtp');

/**
 * Solve the hash problem. This function will try different nonce until it finds one such that the
 * computed hash is less than the `target` difficulty.
 *
 * @param  mtpInput   {Buffer}  80-byte header data to hash
 * @param  target     {Buffer}  32-byte target
 * @param  nonceStart {Buffer}  4-byte nonce to start with.
 * @param  nonceEnd   {Buffer}  4-byte nonce to stop at.
 *
 * @returns {boolean | {
 *     nonce: {Buffer},
 *     hashValue: {Buffer},
 *     hashRoot: {Buffer},
 *     block: {Buffer},
 *     proof: {Buffer}
 * }} False if a nonce was not found, otherwise an object containing nonce and MTP proofs
 * in Buffers.
 */
const result = mtp.hash(mtpInput, target, nonceStart, nonceEnd);
if (!result) {
    throw new Error('Failed to find a nonce that meets the target');
}
```

__Verify__
```js
const mtp = require('hasher-mtp');
const hashValueOut = Buffer.alloc(32);

/**
 * Verify the given input and proofs are valid.
 *
 * This function verifies that the provided `nonce` does produce a hash value
 * that is less than `target`.
 *
 * @param mtpInput     {Buffer}  80-byte header that was hashed.
 * @param nonce        {Buffer}  4-byte nonce to check.
 * @param hashRoot     {Buffer}  16-byte MTP hash root used for verification.
 * @param block        {Buffer}  MTP block data used for verification.
 * @param proof        {Buffer}  NTP proof data used for verification.
 * @param hashValueOut {Buffer}  A 32-byte buffer to put the hash result into.
 *
 * @returns {boolean} True if verification is successful, otherwise false.
 */
const isValid = mtp.verify(mtpInput, nonce, hashRoot, block, proof, hashValueOut);

if (isValid) {
    console.log(hashValueOut.toString('hex'));
}
else {
    console.log('Invalid Proof');
}
```

## Dependencies ##
The Boost library is used.

In Ubuntu:
```
   sudo apt-get install build-essential
   sudo apt-get install libboost-system-dev
```