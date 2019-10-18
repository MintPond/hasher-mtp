"use strict";

const mtp = require('./index.js');

process.title = 'verify-test';

const mtpHeader = createMtpHeader();
const target = uint256BufferFromHash('00fe4f2c5a800008000000000000000000000000000000000000000000000000');

const result = findNonce(mtpHeader, target);

verify(mtpHeader, result, 1000);

function createMtpHeader() {
    return Buffer.from(
        /* version         */ '00000020' +
        /* prev block hash */ 'ab783e17a48c060f9899b7287bf66bc1e9c13eef4e61745db03d0534a3ecb580' +
        /* merkle root     */ '74c6890ff98cf6295fc8b2deb4172e0f4490e4e3f3d720f0fd22491340f35913' +
        /* time            */ '6ff69f5b' +
        /* bits            */ 'ffff0020' +
        /* mtp version     */ '01000000',
        'hex');
}

function findNonce(mtpHeader, target) {

    const nonceStart = Buffer.from('00000000', 'hex');
    const nonceEnd = Buffer.from('FFFFFFFF', 'hex');

    console.log('Finding nonce...');

    const startTime = Date.now();
    const result = mtp.hash(mtpHeader, target, nonceStart, nonceEnd);
    const endTime = Date.now();

    console.log(`Find nonce complete: ${endTime - startTime}ms`);
    console.log(`nonce      = ${result.nonce.readUInt32LE(0)}`);
    console.log(`nonce hex  = ${result.nonce.toString('hex')}`);
    console.log(`hash/sec   = ${result.nonce.readUInt32LE(0) / (endTime - startTime) * 1000}`);

    if (!result) {
        console.log('No valid nonce found');
        return false;
    }

    console.log(`block size = ${result.block.length}`);
    console.log(`proof size = ${result.proof.length}`);

    return result;
}


function verify(mtpHeader, hashResult, iterations) {

    console.log(`Verifying with ${iterations} iterations...`);

    const mtpHashValue = Buffer.alloc(32);
    const startTimeMs = Date.now();
    for (var i = 0; i < iterations; i++) {
        const isVerified = mtp.verify(mtpHeader, hashResult.nonce, hashResult.hashRoot, hashResult.block, hashResult.proof, mtpHashValue);
        if (!isVerified) {
            console.log('Verification failed. Aborting.');
            return;
        }
    }
    const endTimeMs = Date.now();
    const verifyPs = iterations / (endTimeMs - startTimeMs) * 1000;
    console.log(`verify/sec = ${verifyPs}`);
    console.log(`hashValue  = ${mtpHashValue.toString('hex')}`);
}

function uint256BufferFromHash(hex) {

    const buff = Buffer.from(hex, 'hex');
    const reversed = Buffer.alloc(buff.length);
    for (var i = buff.length - 1; i >= 0; i--)
        reversed[buff.length - i - 1] = buff[i];
    return reversed;
}


