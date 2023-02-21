/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

#define pr_fmt(fmt) "elf_verify: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/elf.h>
#include <crypto/akcipher.h>
#include <linux/scatterlist.h>
#include <linux/verification.h>
#include <crypto/pkcs7.h>
#include <crypto/public_key.h>
#include <crypto/hash.h>
#include <linux/oid_registry.h>
#define SHT_SIG_PKEY 0x80736967	/* ((0x80 << 24)|('s' << 16)|('i' << 8)|'g') */
#define SHT_SIG_CERT (SHT_SIG_PKEY + 1)

MODULE_DESCRIPTION("Verify module for elf_sign.");
MODULE_AUTHOR("ningyuv <ningyuv@outlook.com>");
MODULE_LICENSE("GPL");

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION_SAFE.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

static inline void hex_dump(const void *const buf, long long buflen) {
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
		16, 1,
		buf, buflen, false);
}

static inline struct file *open_file(char *kernel_filename) {
	char *pwd_path, *buf, *elf_name;
	struct file* fp = NULL;

	path_get(&current->fs->pwd);
	buf = kmalloc(4096, GFP_KERNEL);
	if (!buf)
		goto out_no_buf_mem;
	pwd_path = d_path(&current->fs->pwd, buf, 4096);
	pr_info("pwd: %s\n", pwd_path);

	elf_name = kmalloc(4096, GFP_KERNEL);
	if (!elf_name)
		goto out_no_name_mem;
	if (kernel_filename[0] == '/') {
		strcpy(elf_name, kernel_filename);
	}
	else {
		strcpy(elf_name, pwd_path);
		strcat(elf_name, "/");
		strcat(elf_name, kernel_filename);
	}
	pr_info("filename: %s\n", elf_name);
	fp = filp_open(elf_name, O_RDONLY, 0);
	if (IS_ERR(fp))
	{
		pr_err("Cannot open file\n");
		goto out;
	}
	pr_info("Opened the file successfully\n");
out:
	kfree(elf_name);
out_no_name_mem:
	kfree(buf);
out_no_buf_mem:
	return fp;
}

static inline int elf_sanity_check32(struct elf32_hdr *elf_hdr)
{
	if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
		pr_err("Binary is not elf format\n");
		return -2;
	}

	if (!elf_hdr->e_shoff) {
		pr_err("No section header!\n");
		return -1;
	}

	if (elf_hdr->e_shentsize != sizeof(Elf32_Shdr)) {
		pr_err("Section header is wrong size!\n");
		return -1;
	}

	if (elf_hdr->e_shnum > 65536U / sizeof(Elf32_Shdr)) {
		pr_err("Too many entries in Section Header!\n");
		return -1;
	}

	return 0;
}

static inline int elf_sanity_check64(struct elf64_hdr *elf_hdr)
{
	if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
		pr_err("Binary is not elf format\n");
		return -2;
	}

	if (!elf_hdr->e_shoff) {
		pr_err("No section header!\n");
		return -1;
	}

	if (elf_hdr->e_shentsize != sizeof(Elf64_Shdr)) {
		pr_err("Section header is wrong size!\n");
		return -1;
	}

	if (elf_hdr->e_shnum > 65536U / sizeof(Elf64_Shdr)) {
		pr_err("Too many entries in Section Header!\n");
		return -1;
	}

	return 0;
}

static inline struct elf64_hdr *read_elf_header(struct file *file)
{
	struct elf64_hdr *elf_ex;
	int retval;
	loff_t offset = 0;

	elf_ex = kmalloc(sizeof(struct elf64_hdr), GFP_KERNEL);
	if (!elf_ex) {
		pr_err ("kmalloc failed for elf_ex\n");
		return ERR_PTR(-ENOMEM);
	}

	kernel_read(file, elf_ex, sizeof(struct elf64_hdr), &offset);

	if (elf_ex->e_ident[EI_CLASS] == ELFCLASS32)
		retval = elf_sanity_check32((struct elf32_hdr *) elf_ex);
	else
		retval = elf_sanity_check64(elf_ex);
	if (retval) {
		kfree(elf_ex);
		if (retval == -1)
			return ERR_PTR(-EINVAL);
		else
			return NULL;
	}

	return elf_ex;
}

static inline char *find_signature(struct file* fp, struct elf64_hdr* elf64_ex, unsigned long long *len, Elf64_Word *sig_type) {
	Elf64_Shdr *sig_shdr;
	char *signature = NULL;
	loff_t sig_shoff;

	sig_shdr = kmalloc(sizeof(Elf64_Shdr), GFP_KERNEL);
	if (!sig_shdr)
		goto out;
	sig_shoff = elf64_ex->e_shoff + sizeof(Elf64_Shdr) * (elf64_ex->e_shnum - 1);
	kernel_read(fp, sig_shdr, sizeof(Elf64_Shdr), &sig_shoff);

	if (sig_shdr->sh_type != SHT_SIG_PKEY && sig_shdr->sh_type != SHT_SIG_CERT)
		goto free_shdr;

	signature = kmalloc(sig_shdr->sh_size, GFP_KERNEL);
	if (!signature)
		goto free_shdr;
	kernel_read(fp, signature, sig_shdr->sh_size, &sig_shdr->sh_offset);
	*len = sig_shdr->sh_size;
	*sig_type = sig_shdr->sh_type;

free_shdr:
	kfree(sig_shdr);
out:
	return signature;
}

static inline int kernel_stat(const char __user *filename, struct kstat *stat)
{
	int ret;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_stat(filename, stat);
	set_fs(old_fs);
	return ret;
}

static inline unsigned char *read_bytes(const char *filename, long long *len) {
	struct file *fp;
	struct kstat *stat;
	unsigned char *buf = NULL;
	loff_t offset = 0;
	fp = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err ("key file open err: %s\n", filename);
		goto out_no_file;
	}
	stat = kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!stat)
		goto out_no_stat;
	kernel_stat(filename, stat);
	buf = kmalloc(stat->size, GFP_KERNEL);
	if (!buf)
		goto out_no_buf_mem;
	kernel_read(fp, buf, stat->size, &offset);
	*len = stat->size;

out_no_buf_mem:
	kfree(stat);
out_no_stat:
	filp_close(fp, NULL);
out_no_file:
	return buf;
}

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
	const unsigned char *data, unsigned int datalen,
	unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int get_hash(const unsigned char *data, unsigned int datalen, unsigned char *digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
		pr_info("can't alloc alg %s, code: %ld\n", hash_alg_name, PTR_ERR(alg));
		return PTR_ERR(alg);
    }
    ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg);
    return ret;
}

static inline unsigned char *get_load1_data(struct file *fp, struct elf64_hdr *elf64_ex, unsigned long long *len) {
	unsigned char *load1_data = NULL;
	Elf64_Phdr *elf64_phdr;
	long long i, ph_offset;
	
	elf64_phdr = kmalloc(sizeof(Elf64_Phdr), GFP_KERNEL);
	if (!elf64_phdr)
		goto out;
	for (i=0;i<elf64_ex->e_phnum;++i) {
		ph_offset = elf64_ex->e_phoff + sizeof(Elf64_Phdr) * i;
		kernel_read(fp, elf64_phdr, sizeof(Elf64_Phdr), &ph_offset);
		if (elf64_phdr->p_type == PT_LOAD)
			break;
	}
	if (elf64_phdr->p_type != PT_LOAD)
		goto free_phdr;
	load1_data = vmalloc(elf64_phdr->p_filesz);
	if (!load1_data)
		goto free_phdr;
	kernel_read(fp, load1_data, elf64_phdr->p_filesz, &elf64_phdr->p_offset);
	*len = elf64_phdr->p_filesz;

	memcpy(load1_data, elf64_ex, sizeof(Elf64_Ehdr));

free_phdr:
	kfree(elf64_phdr);
out:
	return load1_data;
}

static inline unsigned char *get_digest(struct file *fp, struct elf64_hdr *elf64_ex, unsigned long long *len) {
	int ret;
	unsigned char *load1_data, *digest = NULL;
	long long dig_size = 256 / 8, data_len;
	load1_data = get_load1_data(fp, elf64_ex, &data_len);
	if (!load1_data) {
		goto out;
	}
	digest = kmalloc(dig_size, GFP_KERNEL);
	if (!digest)
		goto out_no_dig;
	*len = dig_size;
	ret = get_hash(load1_data, data_len, digest);
	if (ret) {
		pr_err("hash err: %d\n", ret);
		kfree(digest);
		digest = NULL;
	}

out_no_dig:
	vfree(load1_data);
out:
	return digest;
}
struct x509_certificate {
	struct x509_certificate *next;
	struct x509_certificate *signer;	/* Certificate that signed this one */
	struct public_key *pub;			/* Public key details */
	struct public_key_signature *sig;	/* Signature parameters */
	char		*issuer;		/* Name of certificate issuer */
	char		*subject;		/* Name of certificate subject */
	struct asymmetric_key_id *id;		/* Issuer + Serial number */
	struct asymmetric_key_id *skid;		/* Subject + subjectKeyId (optional) */
	time64_t	valid_from;
	time64_t	valid_to;
	const void	*tbs;			/* Signed data */
	unsigned	tbs_size;		/* Size of signed data */
	unsigned	raw_sig_size;		/* Size of sigature */
	const void	*raw_sig;		/* Signature data */
	const void	*raw_serial;		/* Raw serial number in ASN.1 */
	unsigned	raw_serial_size;
	unsigned	raw_issuer_size;
	const void	*raw_issuer;		/* Raw issuer name in ASN.1 */
	const void	*raw_subject;		/* Raw subject name in ASN.1 */
	unsigned	raw_subject_size;
	unsigned	raw_skid_size;
	const void	*raw_skid;		/* Raw subjectKeyId in ASN.1 */
	unsigned	index;
	bool		seen;			/* Infinite recursion prevention */
	bool		verified;
	bool		self_signed;		/* T if self-signed (check unsupported_sig too) */
	bool		unsupported_key;	/* T if key uses unsupported crypto */
	bool		unsupported_sig;	/* T if signature uses unsupported crypto */
	bool		blacklisted;
};
struct pkcs7_signed_info {
	struct pkcs7_signed_info *next;
	struct x509_certificate *signer; /* Signing certificate (in msg->certs) */
	unsigned	index;
	bool		unsupported_crypto;	/* T if not usable due to missing crypto */
	bool		blacklisted;

	/* Message digest - the digest of the Content Data (or NULL) */
	const void	*msgdigest;
	unsigned	msgdigest_len;

	/* Authenticated Attribute data (or NULL) */
	unsigned	authattrs_len;
	const void	*authattrs;
	unsigned long	aa_set;
#define	sinfo_has_content_type		0
#define	sinfo_has_signing_time		1
#define	sinfo_has_message_digest	2
#define sinfo_has_smime_caps		3
#define	sinfo_has_ms_opus_info		4
#define	sinfo_has_ms_statement_type	5
	time64_t	signing_time;

	/* Message signature.
	 *
	 * This contains the generated digest of _either_ the Content Data or
	 * the Authenticated Attributes [RFC2315 9.3].  If the latter, one of
	 * the attributes contains the digest of the the Content Data within
	 * it.
	 *
	 * THis also contains the issuing cert serial number and issuer's name
	 * [PKCS#7 or CMS ver 1] or issuing cert's SKID [CMS ver 3].
	 */
	struct public_key_signature *sig;
};

struct pkcs7_message {
	struct x509_certificate *certs;	/* Certificate list */
	struct x509_certificate *crl;	/* Revocation list */
	struct pkcs7_signed_info *signed_infos;
	u8		version;	/* Version of cert (1 -> PKCS#7 or CMS; 3 -> CMS) */
	bool		have_authattrs;	/* T if have authattrs */

	/* Content Data (or NULL) */
	enum OID	data_type;	/* Type of Data */
	size_t		data_len;	/* Length of Data */
	size_t		data_hdrlen;	/* Length of Data ASN.1 header */
	const void	*data;		/* Content Data (or 0) */
};
extern void x509_free_certificate(struct x509_certificate *cert);
extern struct x509_certificate *x509_cert_parse(const void *data, size_t datalen);
static inline int verify_sign(struct file *fp, struct elf64_hdr *elf64_ex) {
	int ret = -EKEYREJECTED;
	unsigned char *signature, *digest;
	unsigned long long sig_len, dig_len;
	Elf64_Word sig_type;
	
	signature = find_signature(fp, elf64_ex, &sig_len, &sig_type);
	if (!signature) {
		pr_err("nosig!\n");
		goto out;
	}
	pr_info("signature:\n");
	hex_dump(signature, sig_len);

	elf64_ex->e_shnum -= 1;
	elf64_ex->e_shoff -= 11 + sig_len;
	digest = get_digest(fp, elf64_ex, &dig_len);
	if (!digest) {
		pr_err("Cannot get digest\n");
		goto free_sig;
	}
	pr_info("digest:\n");
	hex_dump(digest, dig_len);

	if (sig_type == SHT_SIG_PKEY) {
		struct crypto_akcipher *tfm;
		struct akcipher_request *req;
		DECLARE_CRYPTO_WAIT(wait);
		unsigned char *key;
		unsigned long long key_size;
		struct scatterlist src_tab[2];

		tfm = crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0);
		if (IS_ERR(tfm)) {
			pr_err ("Failed to load tfm.\n");
			ret = PTR_ERR(tfm);
			goto free_dig;
		}
		req = akcipher_request_alloc(tfm, GFP_KERNEL);
		if (!req)
			goto free_tfm;
		key = read_bytes("/elf_verify/pub1.der", &key_size);
		if (!key)
			goto free_req;
		pr_info("key size: %lld\n", key_size);
		ret = crypto_akcipher_set_pub_key(tfm, key, key_size);
		pr_info ("set_key: %d\n", ret);

		sg_init_table(src_tab, 2);
		sg_set_buf(&src_tab[0], signature, sig_len);
		sg_set_buf(&src_tab[1], digest, dig_len);
		akcipher_request_set_crypt(req, src_tab, NULL, sig_len, dig_len);
		akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
			crypto_req_done, &wait);
		ret = crypto_wait_req(crypto_akcipher_verify(req), &wait);
		pr_info("verify ret: %d", ret);

		kfree(key);
	free_req:
		akcipher_request_free(req);
	free_tfm:
		crypto_free_akcipher(tfm);
	}
	else {
		unsigned char *cert;
		unsigned long long cert_len;
		struct x509_certificate *x509;
		struct pkcs7_message *p7;

		cert = read_bytes("/elf_verify/ca.crt", &cert_len);
		if (!cert) {
			goto free_dig;
		}
		x509 = x509_cert_parse(cert, cert_len);
		if (IS_ERR(x509)) {
			goto free_cert;
		}

		p7 = pkcs7_parse_message(signature, sig_len);
		if (!p7) {
			goto free_x509;
		}
		p7->signed_infos->sig->digest = digest;
		p7->signed_infos->sig->digest_size = dig_len;
		ret = public_key_verify_signature(x509->pub, p7->signed_infos->sig);
		p7->signed_infos->sig->digest = NULL;
		p7->signed_infos->sig->digest_size = 0;
		pr_err("pkcs7 verify ret: %d\n", ret);

		pkcs7_free_message(p7);
	free_x509:
		x509_free_certificate(x509);
	free_cert:
		kfree(cert);
	}
free_dig:
	kfree(digest);
free_sig:
	kfree(signature);
out:
	return ret;
}

static inline int do_verify(char *kernel_filename) {
	long ret = -EKEYREJECTED;
	struct file *fp;
	struct elf64_hdr *elf64_ex;

	fp = open_file(kernel_filename);
	if (!fp)
		goto out_no_elf;
	if (IS_ERR(fp)) {
		pr_err("fp is error\n");
		ret = PTR_ERR(fp);
		goto out_no_elf;
	}
	elf64_ex = read_elf_header(fp);
	if (!elf64_ex) {
		pr_err("elf64_ex null pointer!\n");
		ret = 0;
		goto out_no_hdr;
	}
	if (IS_ERR(elf64_ex)) {
		pr_err("elf64_ex is error\n");
		ret = PTR_ERR(elf64_ex);
		goto out_no_hdr;
	}
	ret = verify_sign(fp, elf64_ex);
	if (ret) {
		pr_err("verify failed! code %ld\n", ret);
	}
	else {
		pr_info("verify success!\n");
	}

	kfree(elf64_ex);
out_no_hdr:
	filp_close(fp, NULL);
out_no_elf:
	return ret;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename((void*) regs->di);
	pr_info("execve() before: %s\n", kernel_filename);

	ret = do_verify(kernel_filename);
	if (ret) {
		goto rejected;
	}

	ret = real_sys_execve(regs);

	pr_info("execve() after: %ld\n", ret);
rejected:
	kfree(kernel_filename);

	return ret;
}
#else
static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

static asmlinkage long fh_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename(filename);

	pr_info("execve() before: %s\n", kernel_filename);

	ret = do_verify(kernel_filename);
	if (ret) {
		goto rejected;
	}

	ret = real_sys_execve(filename, argv, envp);

	pr_info("execve() after: %ld\n", ret);
rejected:
	kfree(kernel_filename);
	return ret;
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	pr_info("module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("module unloaded\n");
}
module_exit(fh_exit);
