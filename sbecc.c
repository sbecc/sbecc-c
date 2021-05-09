#include "sbecc.h"
#include <stdio.h>
#include <sodium.h>

#define ERROR_IF_ZERO(result, errorMessage) \
	if (!result)                            \
	{                                       \
		printf(errorMessage);               \
		return 1;                           \
	}

secp256k1_context *ctx;

int sbecc_encrypt(unsigned char *bytes, size_t n_bytes)
{
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	unsigned char nonce[12];
	randombytes_buf(&nonce, sizeof(nonce));

	unsigned char seed32[32];
	randombytes_buf(&seed32, sizeof(seed32));
	ERROR_IF_ZERO(secp256k1_context_randomize(ctx, seed32), "Failed to randomize scep256k1 context.")

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

	// Get shared key
	secp256k1_pubkey serialized_shared_key;
	ERROR_IF_ZERO(secp256k1_ec_pubkey_parse(ctx, &serialized_shared_key, server_pub_key, sizeof(server_pub_key)), "Failed to parse the server public key.");
	ERROR_IF_ZERO(secp256k1_ec_pubkey_tweak_mul(ctx, &serialized_shared_key, priv_key), "Failed to create the shared key.");

	unsigned char sharedKey[65];
	size_t sharedKeySize = sizeof(sharedKey);
	ERROR_IF_ZERO(secp256k1_ec_pubkey_serialize(ctx, sharedKey, &sharedKeySize, &serialized_shared_key, SECP256K1_EC_UNCOMPRESSED), "Failed to serialize the shared key.");

	secp256k1_context_destroy(ctx);
	return 0;
}