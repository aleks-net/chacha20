/*
Based on https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
Written by Aleks Babkov Yatsenko

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
*/
#ifndef CHACHA20_H_INCLUDED
#define CHACHA20_H_INCLUDED

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

struct chacha20_ctx {
	uint32_t keystream32[16];
	size_t pos;
	uint32_t state[16];
};

inline uint32_t _chacha20_pack4(const uint8_t* a) {
	uint32_t out = 0;

	out |= (uint32_t)a[0] << 0 * 8;
	out |= (uint32_t)a[1] << 1 * 8;
	out |= (uint32_t)a[2] << 2 * 8;
	out |= (uint32_t)a[3] << 3 * 8;

	return out;
}

inline uint32_t _chacha20_rotl32(uint32_t x, int n) {
	return (x << n) | (x >> (32 - n));
}

inline void _chacha20_quarter_round(uint32_t* x, uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	x[a] += x[b]; x[d] = _chacha20_rotl32(x[d] ^ x[a], 16);
	x[c] += x[d]; x[b] = _chacha20_rotl32(x[b] ^ x[c], 12);
	x[a] += x[b]; x[d] = _chacha20_rotl32(x[d] ^ x[a], 8);
	x[c] += x[d]; x[b] = _chacha20_rotl32(x[b] ^ x[c], 7);
}

inline void _chacha20_block_next(struct chacha20_ctx* ctx) {
	for (auto i = 0; i < 16; i++)
		ctx->keystream32[i] = ctx->state[i];

	for (auto i = 0; i < 10; i++) {
		_chacha20_quarter_round(ctx->keystream32, 0, 4, 8, 12);
		_chacha20_quarter_round(ctx->keystream32, 1, 5, 9, 13);
		_chacha20_quarter_round(ctx->keystream32, 2, 6, 10, 14);
		_chacha20_quarter_round(ctx->keystream32, 3, 7, 11, 15);
		_chacha20_quarter_round(ctx->keystream32, 0, 5, 10, 15);
		_chacha20_quarter_round(ctx->keystream32, 1, 6, 11, 12);
		_chacha20_quarter_round(ctx->keystream32, 2, 7, 8, 13);
		_chacha20_quarter_round(ctx->keystream32, 3, 4, 9, 14);
	}

	for (auto i = 0; i < 16; i++)
		ctx->keystream32[i] += ctx->state[i];

	ctx->state[3]++;
	if (ctx->state[3] == 0)
		ctx->state[4]++;
}

/*
* Initializes the chacha20 context structure.
*
* It is NOT safe to pass NULL to this function.
*
* \param ctx a chacha20 context structure.
* \param key CHACHA20_KEY_SIZE array.
* \param nonce CHACHA20_NONCE_SIZE array.
* \param counter a uint64_t count.
*/
void chacha20_init(struct chacha20_ctx* ctx, const unsigned char* key, const unsigned char* nonce, uint64_t counter) {
	// constant "expand 32-byte k"
	ctx->state[0] = 0x61707865;
	ctx->state[1] = 0x3320646E;
	ctx->state[2] = 0x79622D32;
	ctx->state[3] = 0x6B206574;

	// key
	ctx->state[4] = _chacha20_pack4(key + 0 * 4);
	ctx->state[5] = _chacha20_pack4(key + 1 * 4);
	ctx->state[6] = _chacha20_pack4(key + 2 * 4);
	ctx->state[7] = _chacha20_pack4(key + 3 * 4);
	ctx->state[8] = _chacha20_pack4(key + 4 * 4);
	ctx->state[9] = _chacha20_pack4(key + 5 * 4);
	ctx->state[10] = _chacha20_pack4(key + 6 * 4);
	ctx->state[11] = _chacha20_pack4(key + 7 * 4);

	// set counter & nonce
	ctx->state[12] = (uint32_t)counter;
	ctx->state[13] = _chacha20_pack4(nonce + 0 * 4) + (uint32_t)(counter >> 32);
	ctx->state[14] = _chacha20_pack4(nonce + 1 * 4);
	ctx->state[15] = _chacha20_pack4(nonce + 2 * 4);

	ctx->pos = 64;
}

/*
* Encrypts/Decrypts the buffer.
*
* It is NOT safe to pass NULL to this function.
*
* \param ctx a chacha20 context structure.
* \param buf buffer to encrypt/decrypt.
* \param len buffer length.
*/
void chacha20_update(struct chacha20_ctx* ctx, unsigned char* buf, size_t len) {
	unsigned char* keystream8 = (unsigned char*)ctx->keystream32;

	for (size_t i = 0; i < len; i++) {
		if (ctx->pos >= 64) {
			_chacha20_block_next(ctx);
			ctx->pos = 0;
		}

		buf[i] ^= keystream8[ctx->pos];
		ctx->pos++;
	}
}

#ifdef __cplusplus
}
#endif

#endif