#include "sbecc.h"
#include <stdio.h>
#include <sodium.h>
#include <string.h>

#define ERROR_IF_ZERO(result, errorMessage) \
	if (!result)                            \
	{                                       \
		printf(errorMessage);               \
		return 1;                           \
	}

secp256k1_context *ctx;

int sbecc_create_context()
{
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	unsigned char seed32[32];
	randombytes_buf(&seed32, sizeof(seed32));

	ERROR_IF_ZERO(secp256k1_context_randomize(ctx, seed32), "Failed to randomize scep256k1 context.");
	return 0;
}

// The header is currently 76 bytes and consists of, in order:
/*
	pubKeyX - 32 bytes
	pubKeyY - 32 bytes
	nonce - 12 bytes
*/
int sbecc_encrypt(unsigned char *header, size_t header_size, unsigned char *script, size_t script_size)
{
	if (ctx == NULL)
	{
		printf("Called sbecc_encrypt without a context.");
		return 1;
	}

	if (header_size != 76)
	{
		printf("Header cannot be less than 76 bytes");
		return 1;
	}

	unsigned char nonce[12];
	randombytes_buf(&nonce, sizeof(nonce));
	memcpy(header + 64, nonce, sizeof(nonce));

	// Create one-session private key
	unsigned char priv_key[32];
	do
	{
		randombytes_buf(&priv_key, sizeof(priv_key));
	} while (!secp256k1_ec_seckey_verify(ctx, priv_key));

	// Create public key
	secp256k1_pubkey pub_key;
	ERROR_IF_ZERO(secp256k1_ec_pubkey_create(ctx, &pub_key, priv_key), "Failed to generate a public key.");

	unsigned char deserialized_pub_key[65];
	size_t deserialized_pub_key_size = sizeof(deserialized_pub_key);
	ERROR_IF_ZERO(secp256k1_ec_pubkey_serialize(ctx, deserialized_pub_key, &deserialized_pub_key_size, &pub_key, SECP256K1_EC_UNCOMPRESSED), "Failed to deserialize the public key.");
	memcpy(header, deserialized_pub_key + 1, 64);

	// Get shared key
	secp256k1_pubkey serialized_shared_key;
	ERROR_IF_ZERO(secp256k1_ec_pubkey_parse(ctx, &serialized_shared_key, server_pub_key, sizeof(server_pub_key)), "Failed to parse the server public key.");
	ERROR_IF_ZERO(secp256k1_ec_pubkey_tweak_mul(ctx, &serialized_shared_key, priv_key), "Failed to create the shared key.");

	unsigned char shared_key[65];
	size_t shared_key_size = sizeof(shared_key);
	ERROR_IF_ZERO(secp256k1_ec_pubkey_serialize(ctx, shared_key, &shared_key_size, &serialized_shared_key, SECP256K1_EC_UNCOMPRESSED), "Failed to serialize the shared key.");

	// The secret key is "rom x turtsis" SHA256-HMAC'd with the key as the shared key (key header byte skipped)

	unsigned char base[] = "rom x turtsis";
	unsigned char secret_key[32];

	crypto_auth_hmacsha256_state state;

	char hmac_success = 0;
	hmac_success += crypto_auth_hmacsha256_init(&state, shared_key + 1, 64);
	hmac_success += crypto_auth_hmacsha256_update(&state, base, sizeof(base) - 1);
	hmac_success += crypto_auth_hmacsha256_final(&state, secret_key);

	// Exclude null terminator at the end of the string
	if (hmac_success != 0)
	{
		printf("Failed to SHA256 HMAC the shared key.");
		return 1;
	}

	// Encrypt the script (it's imperative that the internal counter is set to 1!)
	crypto_stream_chacha20_ietf_xor_ic(script, script, script_size, nonce, 1, secret_key);
	return 0;
}

int sbecc_destroy_context()
{
	if (ctx == NULL)
	{
		printf("Called sbecc_destroy_context without a context.");
		return 1;
	}

	secp256k1_context_destroy(ctx);
	return 0;
}