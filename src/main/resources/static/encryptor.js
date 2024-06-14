// noinspection JSUnusedGlobalSymbols

import {AES as aes, enc, lib, mode, pad} from 'crypto-js';
import {sm4} from 'sm-crypto'

function hexToUint8Array(hexString) {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function base64ToHex(string) {
    return enc.Base64.parse(string).toString(enc.Hex);
}

function exec(call, keyBase64, text) {
    let key = enc.Base64.parse(keyBase64)

    let uint8Array = hexToUint8Array(key.toString(enc.Hex))

    let length = 16;
    let startIndex = (uint8Array.length - length) / 2;

    let iv = uint8Array.slice(startIndex, startIndex + length)

    return call(text, key, {
        mode: mode.CBC,
        padding: pad.Pkcs7,
        iv: lib.WordArray.create(iv)
    })
}

export const SM4 = {
    encrypt(keyBase64, plaintext) {
        let keyHex = hexToUint8Array(
            base64ToHex(keyBase64)
        )
        let result = sm4.encrypt(plaintext, keyHex, {
            mode: 'cbc',
            iv: Uint8Array.from(keyHex).reverse(),
            output: 'array'
        }) ?? []
        return Uint8Array.from(result).buffer;
    },
    decrypt(keyBase64, ciphertext) {
        let keyHex = hexToUint8Array(
            base64ToHex(keyBase64)
        )
        return sm4.decrypt(lib.WordArray.create(ciphertext).toString(enc.Hex), keyHex, {
            mode: 'cbc',
            iv: Uint8Array.from(keyHex).reverse(),
            output: 'string'
        })
    },
    genKey() {
        return lib.WordArray.random(16).toString(enc.Base64)
    }
}
export const AES = {
    encrypt(keyBase64, plaintext) {
        return hexToUint8Array(
            exec(aes.encrypt, keyBase64, plaintext).ciphertext.toString(enc.Hex)
        ).buffer
    },
    decrypt(keyBase64, ciphertext) {
        let wordArray = lib.WordArray.create(ciphertext)
        return exec(aes.decrypt, keyBase64, enc.Base64.stringify(wordArray)).toString(enc.Utf8)
    },
    genKey() {
        return lib.WordArray.random(32).toString(enc.Base64)
    }
};

export function toBase64(data) {
    if (typeof data === 'string') {
        data = enc.Utf8.parse(data)
    }
    return lib.WordArray.create(data).toString(enc.Base64)
}