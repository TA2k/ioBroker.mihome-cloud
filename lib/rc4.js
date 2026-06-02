/*   based on
 *   https://github.com/sipiyou/edomi-roboroc/blob/main/php/cryptRC4.php
 */
/**
 * RC4 encryption/decryption implementation.
 */
class CryptRC4 {
    /**
     * @param {string} [key] Encryption key
     * @param {number} [rounds] Number of PRNG rounds
     */
    constructor(key, rounds) {
        this.setKey(key || '', rounds);
    }

    /**
     * @param {string} key Encryption key
     * @param {number} rounds Number of PRNG rounds
     */
    setKey(key, rounds) {
        const ksa = Array.from({ length: 256 }, (v, k) => k);
        let i = 0;
        let j = 0;

        if (key.length > 0) {
            key = Buffer.from(key);
            const len = key.length;

            for (i = 0; i < 256; i++) {
                j = (j + ksa[i] + key[i % len]) & 255;
                [ksa[i], ksa[j]] = [ksa[j], ksa[i]];
            }

            i = j = 0;

            for (let c = 0; c < rounds; c++) {
                i = (i + 1) & 255;
                j = (j + ksa[i]) & 255;
                [ksa[i], ksa[j]] = [ksa[j], ksa[i]];
            }
        }

        this._ksa = ksa;
        this._idx = i;
        this._jdx = j;
    }

    /**
     * @param {Buffer|string} data Data to encrypt/decrypt
     * @returns {Buffer} Encrypted/decrypted data
     */
    crypt(data) {
        const ksa = (this._ksa || []).slice(0); // Array copy
        let i = this._idx || 0;
        let j = this._jdx || 0;

        const len = data.length;
        const out = Buffer.alloc(len);

        for (let c = 0; c < len; c++) {
            i = (i + 1) & 255;
            j = (j + ksa[i]) & 255;
            [ksa[i], ksa[j]] = [ksa[j], ksa[i]];

            out[c] = data[c] ^ ksa[(ksa[i] + ksa[j]) & 255];
        }

        return out;
    }

    /**
     * @param {string} data UTF-8 string to encode
     * @returns {string} Base64-encoded encrypted string
     */
    encode(data) {
        return this.crypt(Buffer.from(data, 'utf8')).toString('base64');
    }

    /**
     * @param {string} data Base64-encoded encrypted string to decode
     * @returns {string} Decoded UTF-8 string
     */
    decode(data) {
        return this.crypt(Buffer.from(data, 'base64')).toString('utf8');
    }
} //end of RC4 class

module.exports = CryptRC4;
