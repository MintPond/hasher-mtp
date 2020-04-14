hasher-mtp
==========

This is a Node module for simple hashing and verifying inputs using the
MTP (Merkle Tree Proof) proof-of-work algorithm as implemented by [Zcoin](https://zcoin.io). 
Most of the native code comes from or is adapted from [Zcoin code](https://github.com/zcoinofficial/zcoin) 
or the [djm34 cpuminer](https://github.com/zcoinofficial/cpuminer).

This module has been developed and tested on [Node v10.16.3](https://nodejs.org/) and [Ubuntu 16.04](http://releases.ubuntu.com/16.04/)

## Install ##
__Install as Dependency in NodeJS Project__
```bash
# Install from Github git package

sudo apt-get install build-essential
npm install mintpond/hasher-mtp --save
```
-or-
```bash
# Install from Github NPM repository

sudo apt-get install build-essential
npm config set @mintpond:registry https://npm.pkg.github.com/mintpond
npm config set //npm.pkg.github.com/:_authToken <MY_GITHUB_AUTH_TOKEN>

npm install @mintpond/hasher-mtp@2.0.0 --save
```

__Install & Test__
```bash
# Install nodejs v10
curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
sudo apt-get install nodejs -y

# Download hasher-mtp
git clone https://github.com/MintPond/hasher-mtp

# build
cd hasher-mtp
sudo apt-get install build-essential
npm install

# test (requires 6GB of free memory)
npm test
``` 

## Usage ##
__Hash__
```js
const mtp = require('hasher-mtp');

/**
 * Solve the hash problem. This function will try different nonce until it finds one such that the
 * computed hash is less than the `target` difficulty.
 * 
 * A minimum of 6GB of free memory is required.
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
 * This function verifies that the provided proofs are valid and returns the hash value.
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
In Ubuntu:
```
   sudo apt-get install build-essential
```