#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include <err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <argp.h>
#define SHT_SIG_PKEY 0x80736967	/* ((0x80 << 24)|('s' << 16)|('i' << 8)|'g') */
#define SHT_SIG_CERT (SHT_SIG_PKEY + 1)
#define RSA2048_SIG_SIZE 256

#ifdef DEBUG
void hex_dump(unsigned char *buf, size_t size) {
	int i=0;
	while (i<size) {
		printf("%02x ", buf[i]);
		++i;
		if (i%16 == 0)
			printf("\n");
	}
	printf("\n");
}
#endif

static inline size_t read_file(FILE *file, void *buf, size_t size, unsigned long long offset) {
	fseek(file, offset, SEEK_SET);
	return fread(buf, sizeof(char), size, file);
}

static inline int elf_sanity_check32(Elf32_Ehdr *elf_hdr)
{
	if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
		warnx("Binary is not elf format!");
		return -2;
	}

	if (!elf_hdr->e_shoff) {
		warnx("No section header!");
		return -1;
	}

	if (elf_hdr->e_shentsize != sizeof(Elf32_Shdr)) {
		warnx("Section header is wrong size!");
		return -1;
	}

	if (elf_hdr->e_shnum > 65536U / sizeof(Elf32_Shdr)) {
		warnx("Too many entries in Section Header!");
		return -1;
	}

	return 0;
}

static inline int elf_sanity_check64(Elf64_Ehdr *elf_hdr)
{
	if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
		warnx("Binary is not elf format!");
		return -2;
	}

	if (!elf_hdr->e_shoff) {
		warnx("No section header!");
		return -1;
	}

	if (elf_hdr->e_shentsize != sizeof(Elf64_Shdr)) {
		warnx("Section header is wrong size!");
		return -1;
	}

	if (elf_hdr->e_shnum > 65536U / sizeof(Elf64_Shdr)) {
		warnx("Too many entries in Section Header!");
		return -1;
	}

	return 0;
}

static inline Elf64_Ehdr *read_elf_header(FILE *file)
{
	Elf64_Ehdr *elf_ex;
	int retval;

	elf_ex = malloc(sizeof(Elf64_Ehdr));
	if (!elf_ex) {
		warnx("kmalloc failed for elf_ex");
		return NULL;
	}
	read_file(file, elf_ex, sizeof(Elf64_Ehdr), 0);
	if (elf_ex->e_ident[EI_CLASS] == ELFCLASS32)
		retval = elf_sanity_check32((Elf32_Ehdr *) elf_ex);
	else
		retval = elf_sanity_check64(elf_ex);
	if (retval) {
		free(elf_ex);
		return NULL;
	}
	
	return elf_ex;
}

Elf64_Shdr *read_shdr_at_offset(FILE *fp, unsigned long long offset) {
	Elf64_Shdr *shdr;
	int retval;
	
	shdr = malloc(sizeof(Elf64_Shdr));
	if (!shdr) {
		warnx("Cannot allocate memory to read Section Header");
		return NULL;
	}

	retval = read_file(fp, shdr, sizeof(Elf64_Shdr), offset);

	if (ferror(fp) || (unsigned long)retval != sizeof(Elf64_Shdr)) {
		warn("Cannot open elf file");
		return NULL;
	}
	return shdr;
}

Elf64_Shdr *read_shdr_at_ndx(FILE *fp, Elf64_Ehdr *elf_hdr, Elf64_Half shndx) {
	return read_shdr_at_offset(fp, elf_hdr->e_shoff + shndx * sizeof(Elf64_Shdr));
} 

Elf64_Shdr *read_str_shdr(FILE *fp, Elf64_Ehdr *elf_hdr) {
	return read_shdr_at_ndx(fp, elf_hdr, elf_hdr->e_shstrndx);
}
Elf64_Shdr *read_last_shdr(FILE *fp, Elf64_Ehdr *elf_hdr) {
	return read_shdr_at_ndx(fp, elf_hdr, elf_hdr->e_shnum - 1);
}

void append_bytes(FILE *file_out, void *buf, size_t size) {
	fwrite(buf, sizeof(char), size, file_out);
}

void copy_bytes(FILE *file_in, FILE *file_out, long long size) {
	char c;
	if (size < 0) {
		c = fgetc(file_in);
		while(!feof(file_in)) {
			fputc(c, file_out);
			c = fgetc(file_in);
		}
		size = 0;
	}
	while(size-- && !feof(file_in)) {
		c = fgetc(file_in);
		fputc(c, file_out);
	}
}

void write_ehdr(FILE *file_out, Elf64_Ehdr *elf_hdr) {
	fseek(file_out, 0, SEEK_SET);
	fwrite(elf_hdr, sizeof(char), sizeof(Elf64_Ehdr), file_out);
}

void update_signature(FILE *fp, Elf64_Shdr *sig_shdr, void *signature) {
	fseek(fp, sig_shdr->sh_offset, SEEK_SET);
	fwrite(signature, sizeof(char), sig_shdr->sh_size, fp);
}

void update_str_shsize(FILE *fp, Elf64_Ehdr *elf_hdr, Elf64_Shdr *shdr) {
	fseek(fp, elf_hdr->e_shoff + sizeof(Elf64_Shdr) * elf_hdr->e_shstrndx, SEEK_SET);
	fwrite(shdr, sizeof(char), sizeof(Elf64_Shdr), fp);
}

void *get_load1_data(FILE *fp, Elf64_Ehdr *elf_hdr, Elf64_Xword *len) {
	Elf64_Phdr *phdr;
	int i;
	void *load1_data = NULL;

	phdr = malloc(sizeof(Elf64_Phdr));
	if (!phdr) {
		warnx("Cannot alloc phdr memory");
		goto out;
	}
	for(i=0;i<elf_hdr->e_phnum;++i) {
		read_file(fp, phdr, sizeof(Elf64_Phdr), elf_hdr->e_phoff + sizeof(Elf64_Phdr) * i);
		if (phdr->p_type == PT_LOAD) {
			break;
		}
	}
	if (phdr->p_type != PT_LOAD) {
		warnx("no load segment");
		goto free_phdr;
	}

	load1_data = malloc(phdr->p_filesz);
	if (!load1_data) {
		warnx("no load1 data mem");
		goto free_phdr;
	}
	read_file(fp, load1_data, phdr->p_filesz, phdr->p_offset);
	*len = phdr->p_filesz;

free_phdr:
	free(phdr);
out:
	return load1_data;
}

void *get_digest(FILE *fp, Elf64_Ehdr *elf_hdr) {
	void *load1_data, *digest = NULL;
	Elf64_Xword load1_len;

	load1_data = get_load1_data(fp, elf_hdr, &load1_len);
	if (!load1_data) {
		warnx("Cannot read 'load segment' data");
		goto out;
	}

	digest = malloc(SHA256_DIGEST_LENGTH);
	if (!digest) {
		warnx("no dig mem");
		goto free_load;
	}
	SHA256(load1_data, load1_len, digest);
#ifdef DEBUG
	printf("digest:\n");
	hex_dump(digest, SHA256_DIGEST_LENGTH);
#endif
free_load:
	free(load1_data);
out:
	return digest;
}

RSA *read_key(unsigned char *key_path) {
	FILE *fp;
	RSA *key;

	if((fp = fopen(key_path, "r")) == NULL)
    {
        warn( "fopen[%s] failed", key_path);
        return NULL;
    }
	key = PEM_read_RSAPrivateKey(fp, NULL, NULL,NULL);
    if(key == NULL)
    {
        warnx( "PEM_read_RSAPrivateKey failed");
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    return key;
}

void *pkey_gen_sign(FILE *fp, Elf64_Ehdr *elf_hdr, RSA *key, int *len) {
	void *digest, *signature = NULL;
	*len = RSA2048_SIG_SIZE;

	digest = get_digest(fp, elf_hdr);
	if (!digest) {
		warn("no digest");
		goto out;
	}

	signature = malloc(*len);
	if (!signature) {
		warn("no sig mem");
		goto rsa_free;
	}
	RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, len, key);
#ifdef DEBUG
	printf("signature, size: %lu\n", *len);
	hex_dump(signature, *len);
#endif
rsa_free:
	free(digest);
out:
	return signature;
}

void *cert_gen_sign(FILE *fp, Elf64_Ehdr *elf_hdr, EVP_PKEY *key, X509 *cert, int *len) {
	void *load1_data;
	unsigned char *signature = NULL;
	Elf64_Xword load1_len;
	BIO *data;
	PKCS7 *p7;

	load1_data = get_load1_data(fp, elf_hdr, &load1_len);
	if (!load1_data) {
		warn("no load1_data");
		goto out;
	}

	data = BIO_new_mem_buf(load1_data, load1_len);
	if (!data) {
		warnx("Cannot alloc bio");
		goto free_load;
	}
	p7 = PKCS7_sign(cert, key, NULL, data, PKCS7_NOCERTS | PKCS7_DETACHED | PKCS7_NOATTR | PKCS7_BINARY);
	if (!p7) {
		warnx("PKCS#7 sign failed, key and cert may not match");
		goto free_bio;
	}
	*len = i2d_PKCS7(p7, &signature);
	if (*len < 0) {
		warnx("Convert to PKCS#7 failed");
		signature = NULL;
	}

#ifdef DEBUG
	printf("signature, size: %lu\n", *len);
	hex_dump(signature, *len);
#endif
free_p7:
	PKCS7_free(p7);
free_bio:
	BIO_free(data);
free_load:
	free(load1_data);
out:
	return signature;
}

const char *argp_program_version = "elf_sign 1.0";
const char *argp_program_bug_address = "<ningyuv@outlook.com>";
static char doc[] = 
	"Sign a elf file which have at least 1 load segment. For LKM to verify.\n"
	"Add a \".signature\" section contains 256 bytes signature.\n";
static char args_doc[] = "FILE1 [FILE2, FILE3, ...]";
static struct argp_option options[] = {
    { "key", 'k', "file", 0, "PEM format private key to sign a file."},
    { "cert", 'c', "file", 0, "PEM format certificate to sign a file."},
    { "unsign", 'u', 0, 0, "Unsign a file."},
    { 0 }
};

struct arguments {
	char **files;
	char *key_path;
	char *cert_path;
	int cert_sign;
	int unsign;
	int cnt;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
		case 'k': arguments->key_path = arg; break;
		case 'c':
			arguments->cert_path = arg;
			arguments->cert_sign = 1;
			break;
		case 'u': arguments->unsign = 1; break;
		case ARGP_KEY_ARG:
			arguments->files = realloc(arguments->files, sizeof(char *) * (state->arg_num + 1));
			arguments->files[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 1)
				argp_usage(state);
			arguments->cnt = state->arg_num;
		default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

void *gen_sign(struct arguments *arguments, FILE *file_in, Elf64_Ehdr *elf_hdr,int *len) {
	void *signature = NULL;
	if (arguments->cert_sign) {
		EVP_PKEY *key;
		X509 *cert;
		BIO *key_bio, *cert_bio;
		
		key_bio = BIO_new_file(arguments->key_path, "rb");
		key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
		if (!key) {
			warn("Cannot parse key[%s]", arguments->key_path);
			goto out;
		}

		cert_bio = BIO_new_file(arguments->cert_path, "rb");
		cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
		if (!cert) {
			warnx("Cannot parse cert[%s]", arguments->cert_path);
			goto free_key;
		}

		signature = cert_gen_sign(file_in, elf_hdr, key, cert, len);

		X509_free(cert);
		BIO_free(cert_bio);
	free_key:
		EVP_PKEY_free(key);
		BIO_free(key_bio);
	}
	else {
		RSA *key;
		
		key = read_key(arguments->key_path);
		if (!key) {
			goto out;
		}
		signature = pkey_gen_sign(file_in, elf_hdr, key, len);

		RSA_free(key);
	}

out:
	return signature;
}

int sign(struct arguments *arguments, FILE *file_in, Elf64_Ehdr *elf_hdr, Elf64_Shdr *shdr, char *tmp_filename, char *filename) {
	int ret = EXIT_SUCCESS;
	FILE *file_out;
	char sig_shname[] = ".signature";
	int sig_shname_len = sizeof(sig_shname);
	void *signature;
	int sig_len;
	Elf64_Shdr *sig_shdr;
	Elf64_Half i;
	Elf64_Off offset;

	if (!arguments->key_path) {
		warnx("no private key provided");
		ret = 1;
		goto out;
	}
	if (arguments->cert_sign && !arguments->cert_path) {
		warnx("no cert provided");
		goto out;
	}

	file_out = fopen(tmp_filename, "wb+");
	if (!file_out) {
		warn("Cannot create temp file[%s]", tmp_filename);
		ret = 1;
		goto out;
	}

	sig_shdr = read_last_shdr(file_in, elf_hdr);
	if (!sig_shdr) {
		warn("Cannot alloc sig_shdr memory[%s]", filename);
		ret = 1;
		goto close_file_out;
	}

	signature = gen_sign(arguments, file_in, elf_hdr, &sig_len);
	if (!signature) {
		warnx("Cannot generate signature[%s]", filename);
		ret = 1;
		goto free_sig_shdr;
	}

	fseek(file_in, 0, SEEK_SET);
	copy_bytes(file_in, file_out, shdr->sh_offset + shdr->sh_size);
	append_bytes(file_out, sig_shname, sig_shname_len);
	copy_bytes(file_in, file_out, (sig_shdr->sh_offset + sig_shdr->sh_size) - (shdr->sh_offset + shdr->sh_size));
	/* signature begin */
	append_bytes(file_out, signature, sig_len);
	/* signature end */
	copy_bytes(file_in, file_out, elf_hdr->e_shoff - (sig_shdr->sh_offset + sig_shdr->sh_size));

	/* section headers begin */
	copy_bytes(file_in, file_out, sizeof(Elf64_Shdr) * elf_hdr->e_shstrndx);
	shdr->sh_size += sig_shname_len;
	append_bytes(file_out, shdr, sizeof(Elf64_Shdr));
	fseek(file_in, sizeof(Elf64_Shdr), SEEK_CUR);

	// Update sections' offset after .shstrtab section.
	// Usually .shstrtab is the last section,
	// BUT maybe here are some other sections after .shstrtab,
	// such as you want to sign a signed elf file forcefully.
	i = elf_hdr->e_shstrndx;
	memcpy(sig_shdr, shdr, sizeof(Elf64_Shdr)); // for offset calculate if i+1==elf_hdr->e_shnum
	while(i + 1 < elf_hdr->e_shnum) {
		fread(sig_shdr, sizeof(char), sizeof(Elf64_Shdr), file_in);
		sig_shdr->sh_offset += sig_shname_len;
		append_bytes(file_out, sig_shdr, sizeof(Elf64_Shdr));
		++i;
	}

	offset = sig_shdr->sh_offset + sig_shdr->sh_size;
	memcpy(sig_shdr, shdr, sizeof(Elf64_Shdr));
	sig_shdr->sh_offset = offset;
	sig_shdr->sh_name = sig_shdr->sh_size - sig_shname_len;
	sig_shdr->sh_size = sig_len;
	sig_shdr->sh_type = arguments->cert_sign ? SHT_SIG_CERT : SHT_SIG_PKEY;
	append_bytes(file_out, sig_shdr, sizeof(Elf64_Shdr));
	/* section headers end */
	// Maybe here are some garbage bytes after section headers
	copy_bytes(file_in, file_out, -1);

	elf_hdr->e_shnum += 1;
	elf_hdr->e_shoff += sig_shname_len + sig_len;
	write_ehdr(file_out, elf_hdr);

	free(signature);
free_sig_shdr:
	free(sig_shdr);
close_file_out:
	fclose(file_out);
out:
	return ret;
}

int unsign(struct arguments *arguments, FILE *file_in, Elf64_Ehdr *elf_hdr, Elf64_Shdr *shdr, char *tmp_filename, char *filename) {
	int ret = EXIT_FAILURE;
	int sig_shname_len = sizeof(".signature");
	Elf64_Shdr *sig_shdr;
	FILE *file_out;
	Elf64_Half i;

	sig_shdr = read_last_shdr(file_in, elf_hdr);
	if (!sig_shdr) {
		goto out;
	}
	if (sig_shdr->sh_type != SHT_SIG_PKEY && sig_shdr->sh_type != SHT_SIG_CERT) {
		warnx("have not signed[%s]", filename);
		goto free_sig_shdr;
	}

	file_out = fopen(tmp_filename, "wb+");
	if (!file_out) {
		warn("Cannot create temp file[%s]", tmp_filename);
		goto free_sig_shdr;
	}

	fseek(file_in, 0, SEEK_SET);
	copy_bytes(file_in, file_out, shdr->sh_offset + shdr->sh_size - sig_shname_len);
	fseek(file_in, sig_shname_len, SEEK_CUR);
	copy_bytes(file_in, file_out, sig_shdr->sh_offset - (shdr->sh_offset + shdr->sh_size));
	fseek(file_in, sig_shdr->sh_size, SEEK_CUR);
	copy_bytes(file_in, file_out, elf_hdr->e_shoff - (sig_shdr->sh_offset + sig_shdr->sh_size));
	/* section headers begin */
	copy_bytes(file_in, file_out, sizeof(Elf64_Shdr) * elf_hdr->e_shstrndx);
	shdr->sh_size -= sig_shname_len;
	append_bytes(file_out, shdr, sizeof(Elf64_Shdr));
	fseek(file_in, sizeof(Elf64_Shdr), SEEK_CUR);

	// Update sections' offset after .shstrtab section.
	// Usually .shstrtab and .signature is the last two sections,
	// BUT maybe here are some other sections between .shstrtab and .signature,
	// such as you signed a signed elf file forcefully.
	i = elf_hdr->e_shstrndx;
	elf_hdr->e_shoff -= sig_shname_len + sig_shdr->sh_size;
	elf_hdr->e_shnum -= 1;
	while(i + 1 < elf_hdr->e_shnum) {
		fread(sig_shdr, sizeof(char), sizeof(Elf64_Shdr), file_in);
		sig_shdr->sh_offset -= sig_shname_len;
		append_bytes(file_out, sig_shdr, sizeof(Elf64_Shdr));
		++i;
	}
	/* section headers end */
	fseek(file_in, sizeof(Elf64_Shdr), SEEK_CUR);
	copy_bytes(file_in, file_out, -1);

	write_ehdr(file_out, elf_hdr);

	ret = EXIT_SUCCESS;

	fclose(file_out);
free_sig_shdr:
	free(sig_shdr);
out:
	return ret;
}

int process_one(struct arguments *arguments) {
	char *tmp_filename;
	FILE *file_in;
	Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *shdr;
	struct stat stat_in;
	int ret = EXIT_FAILURE;
	char *filename = arguments->files[arguments->cnt];
	file_in = fopen(filename, "rb");
	if (!file_in) {
		warn("Cannot open %s", filename);
		goto out;
	}
	elf_hdr = read_elf_header(file_in);
	if (!elf_hdr) {
		warnx("Cannot read elf header[%s]", filename);
		goto close_file_in;
	}
	shdr = read_str_shdr(file_in, elf_hdr);
	if (!shdr) {
		warnx("Cannot read shdr[%s]", filename);
		goto free_ehdr;
	}

	tmp_filename = malloc(strlen(filename) + 10);
	if (!tmp_filename) {
		warn("Cannot alloc tmp_filename");
		goto free_shdr;
	}
	strcpy(tmp_filename, filename);
	strcat(tmp_filename, ".sig.tmp");

	if (arguments->unsign)
		ret = unsign(arguments, file_in, elf_hdr, shdr, tmp_filename, filename);
	else {
		ret = sign(arguments, file_in, elf_hdr, shdr, tmp_filename, filename);
	}
	if (ret) {
		remove(tmp_filename);
		goto free_all;
	}
	ret = stat(filename, &stat_in);
	ret = chmod(tmp_filename, stat_in.st_mode);
	ret = rename(tmp_filename, filename);

free_all:
	free(tmp_filename);
free_shdr:
	free(shdr);
free_ehdr:
	free(elf_hdr);
close_file_in:
	fclose(file_in);
out:
	return ret;
}

int main(int argc, char **argv) {
	int ret = EXIT_SUCCESS;
	struct arguments arguments;

	arguments.files = NULL;
	arguments.key_path = NULL;
	arguments.cert_path = NULL;
	arguments.cert_sign = 0;
	arguments.unsign = 0;
	arguments.cnt = 0;
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

	while (arguments.cnt--)
	{
#ifdef DEBUG
		printf("%s\n", arguments.files[arguments.cnt]);
#endif
		process_one(&arguments);
	}

out:
	exit(ret);
}
