#include <stdio.h>
#include <gpgme.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>


#define FINGERPRINT "ED35DCE6EC5230C057646443804E35298EF5C816"

#define LONG_KEYID(FINGERPRINT) \
	(FINGERPRINT +(strlen(FINGERPRINT)-16))		// last 64bit of the fingerprint

#define SHORT_KEYID(FINGERPRINT) \
	(FINGERPRINT +(strlen(FINGERPRINT)-8))			// last 32bit of the fingerprint

int print_engine_info() {
	gpgme_engine_info_t info;
	gpgme_error_t err;

	err = gpgme_get_engine_info(&info);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "ERROR: Filed to get engine info!\n");
		return -1;
	}
	printf( "Installed engines: {\n" );
	while(info != NULL) {
		printf( "\t* %s Protocol=%s Version=%s Required-Version=%s Home=%s\n",
		        info->file_name, gpgme_get_protocol_name(info->protocol),
		        info->version, info->req_version, info->home_dir );
		info = info->next;
	}
	printf("}\n");
	return 0;
}

int print_protocol_info() {
	const char *name;

	printf("Supported Protocols: {\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_RSA);
	if (name) printf("\t* %s\n",name);
	name = gpgme_pubkey_algo_name(GPGME_PK_RSA_E);
	if (name) printf("\t* %s\n",name);
	name = gpgme_pubkey_algo_name(GPGME_PK_RSA_S);
	if (name) printf("\t* %s\n",name);
	name = gpgme_pubkey_algo_name(GPGME_PK_ELG_E);
	if (name) printf("\t* %s\n",name);
	name = gpgme_pubkey_algo_name(GPGME_PK_DSA);
	if (name) printf("\t* %s\n",name);
	name = gpgme_pubkey_algo_name(GPGME_PK_ECC);
	if (name) printf("\t* %s\n",name);
	name = gpgme_pubkey_algo_name(GPGME_PK_ELG);
	if (name) printf("\t* %s\n",name);
	name = gpgme_pubkey_algo_name(GPGME_PK_ECDSA);
	if (name) printf("\t* %s\n",name);
	name = gpgme_pubkey_algo_name(GPGME_PK_ECDH);
	if (name) printf("\t* %s\n",name);
	printf("}\n");


	printf("Unsupported Protocols: {\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_RSA);
	if (!name) printf("\t* GPGME_PK_RSA\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_RSA_E);
	if (!name) printf("\t* GPGME_PK_RSA_E\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_RSA_S);
	if (!name) printf("\t* GPGME_PK_RSA_S\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_ELG_E);
	if (!name) printf("\t* GPGME_PK_ELG_E\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_DSA);
	if (!name) printf("\t* GPGME_PK_DSA\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_ECC);
	if (!name) printf("\t* GPGME_PK_ECC\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_ELG);
	if (!name) printf("\t* GPGME_PK_ELG\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_ECDSA);
	if (!name) printf("\t* GPGME_PK_ECDSA\n");
	name = gpgme_pubkey_algo_name(GPGME_PK_ECDH);
	if (!name) printf("\t* GPGME_PK_ECDH\n");
	printf("}\n");

	return 0;
}

int print_hash_info() {
	const char *name;

	printf("Supported Hashs: {\n");
	name = gpgme_hash_algo_name(GPGME_MD_NONE);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_MD5);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_SHA1);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_RMD160);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_MD2);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_TIGER);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_HAVAL);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_SHA256);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_SHA384);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_SHA512);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_SHA224);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_MD4);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_CRC32);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_CRC32_RFC1510);
	if (name) printf("\t* %s\n",name);
	name = gpgme_hash_algo_name(GPGME_MD_CRC24_RFC2440);
	if (name) printf("\t* %s\n",name);
	printf("}\n");


	printf("Unsupported Hashs: {\n");
	name = gpgme_hash_algo_name(GPGME_MD_NONE);
	if (!name) printf("\t* GPGME_MD_NONE\n");
	name = gpgme_hash_algo_name(GPGME_MD_MD5);
	if (!name) printf("\t* GPGME_MD_MD5\n");
	name = gpgme_hash_algo_name(GPGME_MD_SHA1);
	if (!name) printf("\t* GPGME_MD_SHA1\n");
	name = gpgme_hash_algo_name(GPGME_MD_RMD160);
	if (!name) printf("\t* GPGME_MD_RMD160\n");
	name = gpgme_hash_algo_name(GPGME_MD_MD2);
	if (!name) printf("\t* GPGME_MD_MD2\n");
	name = gpgme_hash_algo_name(GPGME_MD_TIGER);
	if (!name) printf("\t* GPGME_MD_TIGER\n");
	name = gpgme_hash_algo_name(GPGME_MD_HAVAL);
	if (!name) printf("\t* GPGME_MD_HAVAL\n");
	name = gpgme_hash_algo_name(GPGME_MD_SHA256);
	if (!name) printf("\t* GPGME_MD_SHA256\n");
	name = gpgme_hash_algo_name(GPGME_MD_SHA384);
	if (!name) printf("\t* GPGME_MD_SHA384\n");
	name = gpgme_hash_algo_name(GPGME_MD_SHA512);
	if (!name) printf("\t* GPGME_MD_SHA512\n");
	name = gpgme_hash_algo_name(GPGME_MD_SHA224);
	if (!name) printf("\t* GPGME_MD_SHA224\n");
	name = gpgme_hash_algo_name(GPGME_MD_MD4);
	if (!name) printf("\t* GPGME_MD_MD4\n");
	name = gpgme_hash_algo_name(GPGME_MD_CRC32);
	if (!name) printf("\t* GPGME_MD_CRC32\n");
	name = gpgme_hash_algo_name(GPGME_MD_CRC32_RFC1510);
	if (!name) printf("\t* GPGME_MD_CRC32_RFC1510\n");
	name = gpgme_hash_algo_name(GPGME_MD_CRC24_RFC2440);
	if (!name) printf("\t* GPGME_MD_CRC24_RFC2440\n");
	printf("}\n");

	return 0;
}


int main(int argc, const char* argv[]) {
	const char *gpgme_version, *gpgme_prot;
	gpgme_error_t err;
	gpgme_ctx_t ctx;
	FILE *fp_sig=NULL, *fp_msg=NULL;
	gpgme_data_t sig=NULL, msg=NULL, plain=NULL, text=NULL;
	gpgme_verify_result_t result;
	int ret;

	gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;

	/* GPGME version check and initialization */
	setlocale(LC_ALL, "");

	gpgme_version = gpgme_check_version(GPGME_VERSION);	// developed for 1.5.1
	if (!gpgme_version) {
		fprintf(stderr, "ERROR: Wrong library on target! Please "
		        "install at least version %s!\n", GPGME_VERSION);
		exit(1);
	}
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
#ifdef LC_MESSAGES
	gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif


	/* Protocol check */
	gpgme_prot = gpgme_get_protocol_name(protocol);
	err = gpgme_engine_check_version(protocol);
	if (!gpgme_prot || err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "ERROR: libgpgme lacks of OpenPGP protocol!\n");
		print_engine_info();
		exit(1);
	}

	printf("started... %s %s\n", gpgme_version, gpgme_prot);

	/* Analyze Engine */
	ret = print_engine_info();
	if (ret != 0) exit(1);
	ret = print_protocol_info();
	if (ret != 0) exit(1);
	ret = print_hash_info();
	if (ret != 0) exit(1);

	fp_sig = fopen(argv[1], "rb");
	if (!fp_sig) {
		fprintf(stderr, "ERROR: Failed to open '%s'!\n", argv[0]);
		exit(1);
	}
	if (argc > 2)
	{
		fp_msg = fopen(argv[2], "rb");
		if (!fp_msg)
		{
			fprintf(stderr, "ERROR: Failed to open '%s'!\n", argv[1]);
			exit(1);
		}
	}

	err = gpgme_new(&ctx);
	if (err !=GPG_ERR_NO_ERROR) {
		char buf[1024];
		gpgme_strerror_r(err, buf, 1024);
		fprintf(stderr, "ERROR: %s\n", buf);
		exit(1);
	}

	gpgme_set_protocol(ctx, protocol);

	err = gpgme_data_new_from_stream(&sig, fp_sig);
	if (err) {
		fprintf(stderr, "ERROR allocating data object: %s\n", gpgme_strerror(err));
		exit(1);
	}
	printf("Loaded signature from '%s'\n", argv[1]);
	if (fp_msg)
	{
		err = gpgme_data_new_from_stream(&msg, fp_msg);
		if (err) {
			fprintf(stderr, "ERROR allocating data object: %s\n", gpgme_strerror(err));
			exit(1);
		}
		printf("Loaded message from '%s'\n", argv[2]);
	}
	else
	{
		err = gpgme_data_new(&plain);
		if (err) {
			fprintf(stderr, "ERROR allocating data object: %s\n", gpgme_strerror(err));
			exit(1);
		}
		printf("Allocated 'plain' data\n");
	}

	err = gpgme_op_verify(ctx, sig, msg, plain);
	if (err)
	{
		fprintf(stderr, "ERROR: signing failed: %s\n", gpgme_strerror(err));
		exit(1);
	}

//	printf( "Public key: %s %s %s\n", FINGERPRINT, LONG_KEYID(FINGERPRINT), SHORT_KEYID(FINGERPRINT) );


	result = gpgme_op_verify_result(ctx);
	if (result) {
		gpgme_signature_t sig;
		int count = 0;

		for(sig = result->signatures; sig; sig = sig->next)
		{
			count += 1;
			if ( !(sig->summary & GPGME_SIGSUM_VALID) ) {
				fprintf(stderr, "ERROR: verfication of signature %d failed: %s\n", count,
				         gpgme_strerror(sig->status));
				exit(1);
			}
			if (strcmp(sig->fpr, FINGERPRINT) != 0) {
				fprintf(stderr, "ERROR: invalid public key - %s vs %s\n", sig->fpr, FINGERPRINT);
				exit(1);
			}
		}
	}

	printf( "\nSignature verfication successful. Plaintext:\n" );


	text = plain ? plain : msg;
	gpgme_data_seek(text, 0, SEEK_SET);
	size_t bytes;
	do {
		char buffer[256];
		bytes = gpgme_data_read(text, buffer, 256-1);
		buffer[bytes] = '\0';

		printf( "%s", buffer );
	} while( bytes > 0 );

	gpgme_data_release(plain);
	gpgme_data_release(msg);
	gpgme_data_release(sig);

	gpgme_release(ctx);

	return 0;
}
