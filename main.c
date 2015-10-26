#include <stdio.h>
#include <gpgme.h>
#include <locale.h>
#include <stdlib.h>




int print_engine_info() {
	gpgme_engine_info_t info;
	gpgme_error_t err;

	err = gpgme_get_engine_info(&info);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "ERROR: Filed to get engine info!\n");
		return -1;
	}
	printf( "Installed engines: {\n" );
	while (info != NULL) {
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

#define nonnull(STRING) (STRING==NULL?"(null)":STRING)

static void
print_result (gpgme_verify_result_t result)
{
	gpgme_signature_t sig;
	int count = 0;

	printf ("Original file name: %s\n", nonnull(result->file_name));
	for (sig = result->signatures; sig; sig = sig->next)
	{
		printf ("Signature %d\n", count++);
		printf ("  status ....: %s\n", gpgme_strerror (sig->status));
		printf ("  summary ...: %x\n", sig->summary);
		printf ("  fingerprint: %s\n", nonnull (sig->fpr));
		printf ("  created ...: %lu\n", sig->timestamp);
		printf ("  expires ...: %lu\n", sig->exp_timestamp);
		printf ("  validity ..: %d\n", sig->validity);
		printf ("  val.reason : %s\n", gpgme_strerror (sig->status));
		printf ("  pubkey algo: %d\n", sig->pubkey_algo);
		printf ("  digest algo: %d\n", sig->hash_algo);
		printf ("  pka address: %s\n", nonnull (sig->pka_address));
		printf ("  pka trust .: %s\n",
		sig->pka_trust == 0? "n/a" :
		sig->pka_trust == 1? "bad" :
		sig->pka_trust == 2? "okay": "RFU");
		printf ("  other flags:%s%s\n", sig->wrong_key_usage? " wrong-key-usage":"", sig->chain_model? " chain-model":"");
		printf ("  notations .: %s\n",
		sig->notations? "yes":"no");
	}
}



int main(int argc, const char* argv[]) {
	const char *gpgme_version, *gpgme_prot;
	gpgme_error_t err;
	gpgme_ctx_t ctx;
	FILE *fp_sig=NULL, *fp_msg=NULL;
	gpgme_data_t sig=NULL, msg=NULL, plain=NULL;
	gpgme_verify_result_t result;
	int ret;

	gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;

	/* GPGME version check and initialization */
	setlocale (LC_ALL, "");

	gpgme_version = gpgme_check_version(GPGME_VERSION);	// developed for 1.5.1
	if (!gpgme_version) {
		fprintf(stderr, "ERROR: Wrong libgpgme version detected. Please "
		        "install at least %s!\n", GPGME_VERSION);
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

	fp_sig = fopen(argv[0], "rb");
	if (!fp_sig) {
		fprintf(stderr, "ERROR: Failed to open '%s'!\n", argv[0]);
		exit(1);
	}
	if (argc > 1)
	{
		fp_msg = fopen(argv[1], "rb");
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
		fprintf (stderr, "ERROR allocating data object: %s\n", gpgme_strerror (err));
		exit (1);
	}
	if (fp_msg)
	{
		err = gpgme_data_new_from_stream(&msg, fp_msg);
		if (err) {
			fprintf (stderr, "ERROR allocating data object: %s\n", gpgme_strerror (err));
			exit (1);
		}
	}
	else
	{
		gpgme_data_new(&plain);
	}

	err = gpgme_op_verify(ctx, sig, msg, plain);
	if (err)
	{
		fprintf (stderr, "ERROR: signing failed: %s\n", gpgme_strerror (err));
		exit (1);
	}


	result = gpgme_op_verify_result (ctx);
	if (result) {
		print_result (result);
	}

	gpgme_data_release (msg);
	gpgme_data_release (sig);

	gpgme_release (ctx);

	return 0;
}
