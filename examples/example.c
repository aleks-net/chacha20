#include <stdio.h>
#include <string.h>

#include "../chacha20.h"

const unsigned char key[CHACHA20_KEY_SIZE] = {0xcb, 0xd9, 0xe1, 0x92, 0xdf, 0xd7, 0x83, 0x82, 0x89, 0x27, 0x7d, 0x9c, 0xa, 0xed, 0xda, 0xf1, 0x63, 0x6, 0xc7, 0x9a, 0x0, 0xef, 0x73, 0xe0, 0xd6, 0x21, 0x5d, 0x50, 0xa3, 0x43, 0x5b, 0x92};
const unsigned char nonce[CHACHA20_NONCE_SIZE] = {0x9a, 0x96, 0xd1, 0x10, 0x2f, 0xa6, 0x98, 0x40, 0xe, 0x74, 0x2b, 0x84};

int main(int argc, char* argv[]) {
	printf("C Example\n\n");

	char* lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec condimentum, enim vitae ullamcorper congue, velit lacus condimentum sapien, eu convallis nisl neque a eros. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis mauris ante, fringilla non fermentum sit amet, tempor nec augue. Aenean eu vestibulum orci, quis blandit sapien. Praesent condimentum ullamcorper libero vel hendrerit. Nulla bibendum arcu sit amet sagittis mollis. Sed mattis in orci eu tincidunt. Pellentesque in nibh quis tellus malesuada ultricies sit amet vitae ex. Suspendisse eget congue nibh. Nullam metus metus, convallis ut imperdiet lacinia, sagittis at lorem. Sed nec dictum dolor. Vestibulum et efficitur ante. Mauris ipsum tortor, aliquet sed facilisis in, finibus ac tortor.";
	size_t lorem_len = strlen(lorem);

	printf("Original:\n%s\n\n", lorem);

	struct chacha20_ctx ctx;

	// encrypt
	chacha20_init(&ctx, key, nonce, 0);
	chacha20_update(&ctx, (unsigned char*)lorem, lorem_len);

	printf("Encrypted:\n%s\n\n", lorem);

	// decrypt
	chacha20_init(&ctx, key, nonce, 0);
	chacha20_update(&ctx, (unsigned char*)lorem, lorem_len);

	printf("Decrypted:\n%s\n\n", lorem);

	return 0;
}