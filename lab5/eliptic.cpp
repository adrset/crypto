#include <unistd.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdio>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h> 
#include <openssl/ecdh.h>

#include <openssl/evp.h>
#include <cstring>
const std::string OUT_FOLDER = "out";

typedef struct EC_Params {
	EC_Params() {};
	std::vector<unsigned char> a;
	std::vector<unsigned char> b;
	std::vector<unsigned char> p;
	std::vector<unsigned char> order;
	std::vector<unsigned char> x;
	std::vector<unsigned char> y;
} EC_Params;

void handleErrors() {
	std::cerr << "An error has been encountered!" << std::endl;

}


EC_GROUP* create_curve(EC_Params& params) {
	std::cout << std::endl << std::endl << std::endl;
	std::cout << "\n1) Creating group" << std::endl;
	BN_CTX* ctx;
	EC_GROUP* curve;
	BIGNUM* a, * b, * p, * order, * x, * y;
	EC_POINT* generator;

	/* Binary data for the curve parameters */
	unsigned char a_bin[28] =
	{ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE };
	unsigned char b_bin[28] =
	{ 0xB4,0x05,0x0A,0x85,0x0C,0x04,0xB3,0xAB,0xF5,0x41,
		0x32,0x56,0x50,0x44,0xB0,0xB7,0xD7,0xBF,0xD8,0xBA,
		0x27,0x0B,0x39,0x43,0x23,0x55,0xFF,0xB4 };
	unsigned char p_bin[28] =
	{ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01 };
	// Euler function value, basically number points in a group F_p
	unsigned char order_bin[28] =
	{ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0x16,0xA2,0xE0,0xB8,0xF0,0x3E,
		0x13,0xDD,0x29,0x45,0x5C,0x5C,0x2A,0x3D };
	unsigned char x_bin[28] =
	{ 0xB7,0x0E,0x0C,0xBD,0x6B,0xB4,0xBF,0x7F,0x32,0x13,
		0x90,0xB9,0x4A,0x03,0xC1,0xD3,0x56,0xC2,0x11,0x22,
		0x34,0x32,0x80,0xD6,0x11,0x5C,0x1D,0x21 };
	unsigned char y_bin[28] =
	{ 0xbd,0x37,0x63,0x88,0xb5,0xf7,0x23,0xfb,0x4c,0x22,
		0xdf,0xe6,0xcd,0x43,0x75,0xa0,0x5a,0x07,0x47,0x64,
		0x44,0xd5,0x81,0x99,0x85,0x00,0x7e,0x34 };

	/* Set up the BN_CTX */
	if (NULL == (ctx = BN_CTX_new())) handleErrors();
	if (NULL == (a = BN_bin2bn(a_bin, 28, NULL))) handleErrors();
	if (NULL == (b = BN_bin2bn(b_bin, 28, NULL))) handleErrors();
	if (NULL == (p = BN_bin2bn(p_bin, 28, NULL))) handleErrors();
	if (NULL == (order = BN_bin2bn(order_bin, 28, NULL))) handleErrors();
	if (NULL == (x = BN_bin2bn(x_bin, 28, NULL))) handleErrors();
	if (NULL == (y = BN_bin2bn(y_bin, 28, NULL))) handleErrors();
	/* Set the values for the various parameters */
	//if(NULL == (a = BN_bin2bn(params.a.data(), params.a.size(), NULL))) handleErrors();
	//if(NULL == (b = BN_bin2bn(params.b.data(), params.b.size(), NULL))) handleErrors();
	//if(NULL == (p = BN_bin2bn(params.p.data(), params.p.size(), NULL))) handleErrors();
	//if(NULL == (order = BN_bin2bn(params.order.data(), params.order.size(), NULL))) handleErrors();
	//if(NULL == (x = BN_bin2bn(params.x.data(), params.x.size(), NULL))) handleErrors();
	//if(NULL == (y = BN_bin2bn(params.y.data(), params.y.size(), NULL))) handleErrors();

	/* Create the curve */
	if (NULL == (curve = EC_GROUP_new_curve_GFp(p, a, b, ctx))) handleErrors();

	/* Create the generator */
	if (NULL == (generator = EC_POINT_new(curve))) handleErrors();
	if (1 != EC_POINT_set_affine_coordinates_GFp(curve, generator, x, y, ctx))
		handleErrors();

	/* Set the generator and the order */
	if (1 != EC_GROUP_set_generator(curve, generator, order, NULL))
		handleErrors();

	EC_POINT_free(generator);
	BN_free(y);
	BN_free(x);
	BN_free(order);
	BN_free(p);
	BN_free(b);
	BN_free(a);
	BN_CTX_free(ctx);

	return curve;
}

struct DHEntity {
	BIGNUM const* prv;
	EC_POINT* pub;
	EC_KEY* keyPair;
	BIGNUM* x;
	BIGNUM* y;
};


std::vector<unsigned char> getParam(std::string paramName) {

	std::cout << std::endl << "Please specify eliptic curve parameters: " << paramName << std::endl;

	long long unsigned int in;
	std::cin >> in;
	std::cout << in << " provided" << std::endl;

	std::vector<unsigned char>a = std::vector<unsigned char>(sizeof(long long unsigned int));
	for (unsigned int ii = 0; ii < sizeof(long long unsigned int); ii++) {
		a[(sizeof(long long unsigned int) - 1) - ii] = (in >> ((sizeof(long long unsigned int) - 1) - ii) * 8) & 0xff;
		//std::cout << ((sizeof(long long unsigned int)-1) - ii) << "shift by" << ((sizeof(long long unsigned int)-1) - ii)*8 << std::endl;
	}

	for (unsigned int ii = 0; ii < sizeof(long long unsigned int); ii++) {
		printf("%02x", a[ii]);
	}

	return a;
}

void printSecret(DHEntity* a, DHEntity* b, bool invert = 0) {
	if (invert) {
		std::cout << "3b) Entity B got Entity A's public and computes d_B * Q_A" << std::endl;
	}
	else {
		std::cout << "3a) Entity A got Entity B's public and computes d_A * Q_B" << std::endl;
	}
	unsigned char* secret;
	int degree;
	size_t len;
	int i;

	degree = EC_GROUP_get_degree(EC_KEY_get0_group(a->keyPair));
	len = (degree + 7) / 8;
	secret = OPENSSL_malloc(len);
	std::cout << std::endl << std::endl;

	len = ECDH_compute_key(secret, len, b->pub, a->keyPair, NULL);
	std::cout << "=============SECRET BEGIN==============" << std::endl;
	for (i = 0; i < len; i++)
		printf("%02X", secret[i]);
	std::cout << std::endl << "=============+SECRET  END+==============" << std::endl;
	std::cout << std::endl << std::endl;
	OPENSSL_free(secret);

}

DHEntity* generateKey(EC_GROUP* curve) {
	std::cout << "2) Entity gets it's keypair (d, Q) = (priv, pub)" << std::endl;

	BN_CTX* ctx = BN_CTX_new();
	DHEntity* ent = new DHEntity();
	EC_KEY* key = EC_KEY_new();
	// Attach group to key
	std::cout << std::endl;
	EC_KEY_set_group(key, curve);
	// Generate Key
	EC_KEY_generate_key(key);
	EC_KEY_check_key(key);
	ent->keyPair = key;
	ent->prv = EC_KEY_get0_private_key(key);
	ent->pub = EC_KEY_get0_public_key(key);
	ent->x = BN_new();
	ent->y = BN_new();
	int status = EC_POINT_get_affine_coordinates_GFp(curve, ent->pub, ent->x, ent->y, ctx);
	char buff[100];
	if (status) {
		std::cout << "\n\nPublic key is represented by a point on the curve" << std::endl;
		printf("Q(x, y): (%s, %s)\n\n", BN_bn2hex(ent->x), BN_bn2hex(ent->y));
	}
	else {
		handleErrors();
	}
	return ent;
}


void signAndVerify(EC_GROUP* curve) {
	// Create empty key
	EC_KEY* key = EC_KEY_new();
	// Attach group to key
	std::cout << std::endl;
	EC_KEY_set_group(key, curve);
	// Generate Key
	EC_KEY_generate_key(key);
	EC_KEY_check_key(key);
	// We need to store the private key in EVP_PKEY
	EVP_PKEY* pkey = EVP_PKEY_new();

	BIGNUM const* prv = EC_KEY_get0_private_key(key);
	EC_POINT const* pub = EC_KEY_get0_public_key(key);
	printf("%s\n", BN_bn2dec(prv));
	std::cout << (pub) << std::endl;

	unsigned char* hashedMSG = "NOT HASHED MESSAGE";
	ECDSA_SIG* sign = ECDSA_do_sign(hashedMSG, strlen((char*)hashedMSG), key);
	if (sign == 0) {
		std::cerr << "Verification :" << "EXCEPTION" << std::endl;
		return;
	}

	std::string ret = (ECDSA_do_verify(hashedMSG, strlen((char*)hashedMSG), sign, key) ? "true" : "false");
	std::cout << "Verification :" << ret << std::endl;
}



int main(int argc, char** argv) {
	EC_Params params;
	params.a = getParam("a");
	params.b = getParam("b");
	params.p = getParam("p");
	params.order = getParam("o");
	params.x = getParam("x");
	params.y = getParam("y");
	// Create an EC_GROUP : Create Galois Field (finite group) of integers from 0 to p-1. p is a prime! Curve: y^2 mod p = x^3 +ax + b mod p 
	// https://www.openssl.org/docs/man1.0.2/man3/EC_GROUP_new.html
	// https://en.wikipedia.org/wiki/Elliptic_curve params must obey this
	EC_GROUP* curve = create_curve(params);
	// https://www.openssl.org/docs/man1.0.2/man3/EC_KEY_generate_key.html
	// https://pl.wikipedia.org/wiki/Protok%C3%B3%C5%82_Diffiego-Hellmana
	DHEntity* bob = generateKey(curve);
	DHEntity* alice = generateKey(curve);
	printSecret(alice, bob);
	printSecret(bob, alice, true);

	signAndVerify(curve);
}


