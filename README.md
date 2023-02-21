# elf_sign_verify
A method of elf executable signing and verification on Linux

# tested environments

- deepin15.11 amd64(Linux Kernel v4.15.0)
- deepin20beta amd64(Linux Kernel v5.3.0)

# elf_sign
A user-space sign tool for elf executable. It can:
- add signature to elf executable
- nest add signatures to signed elf executable
- remove signature from elf executable
- batch add signatures for some elf executables

## compile (example on ubuntu based OS)
```bash
sudo apt install linux-headers-`uname -r` libssl-dev build-essential
cd elf_sign
make
# will generate elf_sign executable
```

## usage
```bash
$ /path/to/elf_sign -?
Usage: elf_sign [OPTION...] FILE1 [FILE2, FILE3, ...]
Sign a elf file which have at least 1 load segment. For LKM to verify.
Add a ".signature" section contains signature bytes.

  -c, --cert=file            PEM format certificate to sign a file.
  -k, --key=file             PEM format private key to sign a file.
  -u, --unsign               Unsign a file.
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

# elf_verify

A kernel-space program (linux kernel module) to verify elf executables
- **only** elf executables with complete signatures will be allowed to execute (including common programs like `ls`, `cat`, `sudo`, etc)
- else return `-EKEYREJECTED` (-129)

## compile
```bash
sudo apt install linux-headers-`uname -r` libssl-dev build-essential
cd elf_verify
make
# will generate elf_verify.ko linux kernel module
```

## installation
```bash
sudo insmod elf_verify.ko
# then it will automatic verify ALL elf executables
```

# test setup

## 部署方法

### 生成密钥对

```bash
$ openssl genrsa -out rsa_priv_key.pem # 生成私钥
$ openssl rsa -in rsa_priv_key.pem -RSAPublicKey_out -outform der -out pub1.der # 导出公钥
$ sudo mkdir /elf_verify
$ sudo mv pub1.der /elf_verify/ # 放置公钥
```

### 生成证书

```bash
$ openssl req -x509 -new -nodes -key /path/to/rsa_priv_key.pem -sha256 -days 3600 -out ca.pem
$ openssl x509 -in ca.pem -outform der -out ca.crt
$ sudo mv ca.crt /elf_verify/
```

### 为签名工具自身签名

```bash
$ /path/to/elf_sign /path/to/elf_sign -k /path/to/rsa_priv_key.pem
```

### 为一些重要程序签名

```bash
$ sudo /path/to/elf_sign /usr/bin/sudo -k /path/to/rsa_priv_key.pem
$ sudo /path/to/elf_sign /usr/bin/dmesg -k /path/to/rsa_priv_key.pem
$ sudo /path/to/elf_sign /sbin/rmmod -k /path/to/rsa_priv_key.pem
$ sudo /path/to/elf_sign /usr/lib/fprintd/fprintd -k /path/to/rsa_priv_key.pem
```

## 测试方法

### 加载验证模块

```bash
$ sudo insmod /path/to/elf_verify.ko
```

### 基于公私钥的签名与验证

#### `/usr/bin/ls`

```bash
$ ls # 未签名无法运行
$ sudo /path/to/elf_sign /usr/bin/ls -k /path/to/rsa_priv_key.pem
$ ls # 可以运行
$ sudo /path/to/elf_sign /usr/bin/readelf -k /path/to/rsa_priv_key.pem # 为readelf签名
$ sudo /path/to/elf_sign /usr/bin/objdump -k /path/to/rsa_priv_key.pem # 为objdump签名
$ readelf -S /usr/bin/ls # 可以看到ls程序多了.signature节，类型为0x736967
$ objdump -sj .signature /usr/bin/ls # 可以看到签名节的数据
```

#### `/usr/bin/gedit`

```bash
$ gedit test.c # 未签名无法运行
$ sudo /path/to/elf_sign /usr/bin/gedit -k /path/to/rsa_priv_key.pem
$ gedit test.c # 可以运行
```

> 也可以使用图形方式打开`gedit`，前提是启动过程中调起的程序也要被签名，详见演示视频

#### `/opt/google/chrome/chrome`

```bash
# 使用图标启动chrome，无法启动
# 为/usr/bin/文件夹下所有ELF可执行程序签名
$ sudo /path/to/elf_sign /usr/bin/* -k /path/to/rsa_priv_key.pem
# 为chrome程序签名
$ sudo /path/to/elf_sign /opt/google/chrome/chrome -k /path/to/rsa_priv_key.pem
# 使用图标启动chrome，可以运行
```

### 基于证书的签名与验证

#### `/usr/bin/ls`

```bash
$ sudo /path/to/elf_sign /usr/bin/ls -u # 撤销ls程序先前的签名
$ sudo /path/to/elf_sign /usr/bin/ls -k /path/to/rsa_priv_key.pem -c /path/to/ca.pem
$ readelf -S /usr/bin/ls # 可以看到ls程序多了.signature节，类型为0x736968
$ objdump -sj .signature /usr/bin/ls # 可以看到签名节的数据
```

#### `/usr/bin/gedit`

```bash
$ sudo /path/to/elf_sign /usr/bin/gedit -u # 撤销先前的签名
$ sudo /path/to/elf_sign /usr/bin/gedit -k /path/to/rsa_priv_key.pem -c /path/to/ca.pem
$ gedit test.c # 可以运行
```

#### `/opt/google/chrome/chrome`

```bash
$ sudo /path/to/elf_sign /opt/google/chrome/chrome -u # 撤销先前的签名
$ sudo /path/to/elf_sign /opt/google/chrome/chrome -k /path/to/rsa_priv_key.pem -c /path/to/ca.pem
# 启动chrome，可以运行
```

# 基本定义

包含签名信息的新`Section`：

- 名称：`.signature`

- 类型：

  - 基于公私钥的签名：`SHT_SIG_PKEY = 0x80736967`

    >  0x80736967的含义为`(0x80 << 24)|('s' << 16)|('i' << 8)|'g'`

  - 基于证书的签名：`SHT_SIG_CERT = (SHT_SIG_PKEY + 1)`
<!-- more -->
- 数据格式：`blob`

  - 基于公私钥的签名：固定长度的`blob`
  - 基于证书的签名：`pkcs7 message`格式

- 大小：

  - 基于公私钥的签名：256字节

    > 256字节对应强度为RSA 2048

  - 基于证书的签名：长度随证书的`issuer`变化

验证模块返回值：

- 通过验证：返回程序执行结果

- 未通过验证：返回`-EKEYREJECTED`(-129)

  > 命令行提示`键值被服务所拒绝`或`key was rejected by service`

# 实现原理

## 概述

签名程序使用了`libssl`，首先读取ELF文件的`load segment`，对于不同的签名方式（公私钥/证书）使用不同的方法对`load segment`签名得到`signature`，将`signature`作为新的`section`添加到ELF文件尾部。

验证模块是Linux内核模块，可动态加载和移除，运行在内核空间。其使用`ftrace hook`挂钩了`sys_execve`内核函数，在每一个程序执行前，读取ELF文件，对其进行签名校验，只有校验通过的ELF可执行程序才可以运行。

## 内核函数钩子

有许多hook内核函数/系统调用的方式，包括`Linux Security API`，修改系统调用表，`kprobes`等。

尝试过后发现这些都有缺点：

- `Linux Security API(LSM)`不能动态加载
- 修改系统调用表涉及汇编语言
- `kprobes`技术复杂度较高且开销较大

最终选择了`ftrace`框架，挂钩了`sys_execve`内核函数。当验证通过时，执行`real_sys_execve`按正常流程执行程序，否则跳过程序执行流程并返回错误值。

在参考资料所提供的示意图中，标注了验证时机：

![Linux_Kernel_Function_Tracing_hooking](https://user-images.githubusercontent.com/25382292/220274733-40bc3309-5ad7-40ad-bd57-2c359f245645.jpg)

在`Kernel v4.17.0`时，`sys_execve`函数的形参发生改变，所以需要设置编译条件来适配不同内核的系统，如`deepin15.11`和`deepin20beta`

```c
// kernel v4.17.0及之后，sys_execve系统函数形参变为struct pt_regs *regs
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs) {...}
#else
static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

static asmlinkage long fh_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp) {...}
#endif
```

## 生成/验证签名

首先需要确定加密算法和散列算法。可以通过`less /proc/crypto`命令查看和检索系统支持的加密算法和散列算法。`deepin15.11 amd64`和`deepin20beta amd64`的内核都支持`pkcs1pad(rsa,sha256)`加密算法和`sha256`散列算法，故该实现选用`pkcs1pad(rsa,sha256)`加密算法和`sha256`散列算法。

### 签名程序

签名程序通过`libssl`读取私钥、证书、生成签名字节等，首先读取ELF文件的第一个`Load Segment`，

对于不同的签名方式：

- 基于公私钥的签名：
  - 将读取到的字节使用`sha256`算法进行散列得到`digest`
  - 调用`RSA_sign`方法，使用指定的私钥对digest进行签名
- 基于证书的签名：
  - 调用`PKCS7_sign`方法，使用指定的私钥和证书，对读取到的`Load Segment`进行签名
  - `PKCS7_sign`已包含了散列过程

最后得到`signature`，将`signature`写入ELF文件并修正ELF头等，具体过程见下一小节。

### 验证模块

> 验证模块由于处于内核空间，不能使用用户空间的相关库，所以选用`Linux Kernel Crypto API`来完成签名的校验工作。

通过对内核函数的hook，可以得到当前执行程序的路径，该路径可能是绝对路径或相对路径。对于相对路径，需要先利用`current`指针获取到当前工作目录，连接为绝对路径，才能使用`filp_open`函数打开ELF文件。

```c
// 内核中获取当前工作目录示例
// 省略了错误处理和内存释放
path_get(&current->fs->pwd);
buf = kmalloc(4096, GFP_KERNEL);
pwd_path = d_path(&current->fs->pwd, buf, 4096);
pr_info("pwd: %s\n", pwd_path);
```

能够对ELF文件进行读取之后

- 尝试读取签名。读取最后一个`section`的`header`，判断类型是否`SHT_SIG_PKEY`或`SHT_SIG_CERT`，如果是就读取签名`signature`，否则因没有签名验证失败。

- 读取第一个`load segment`的数据，并使用`sha256`散列算法得到`digest`

- 对于不同的签名节类型

  - SHT_SIG_PKEY：

    - 读取公钥`/elf_verify/pub1.der`，调用`Linux Crypto API`相关接口，进行验证

    - ```c
      // 基于公私钥的签名验证示例
      // 省略了错误处理和内存释放
      tfm = crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0);
      req = akcipher_request_alloc(tfm, GFP_KERNEL);
      key = read_bytes("/elf_verify/pub1.der", &key_size);
      ret = crypto_akcipher_set_pub_key(tfm, key, key_size);
      sg_init_table(src_tab, 2);
      sg_set_buf(&src_tab[0], signature, sig_len);
      sg_set_buf(&src_tab[1], digest, dig_len);
      akcipher_request_set_crypt(req, src_tab, NULL, sig_len, dig_len);
      akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                    crypto_req_done, &wait);
      ret = crypto_wait_req(crypto_akcipher_verify(req), &wait);
      pr_info("verify ret: %d", ret);
      ```

  - SHT_SIG_CERT

    - 读取证书`/elf_verify/ca.crt`，解析证书和`pkcs7 message`，并进行验证

    - ```c
      // 基于证书的签名验证示例
      // 省略了错误处理和内存释放
      cert = read_bytes("/elf_verify/ca.crt", &cert_len);
      x509 = x509_cert_parse(cert, cert_len);
      p7 = pkcs7_parse_message(signature, sig_len);
      p7->signed_infos->sig->digest = digest;
      p7->signed_infos->sig->digest_size = dig_len;
      ret = public_key_verify_signature(x509->pub, p7->signed_infos->sig);
      pr_info("pkcs7 verify ret: %d\n", ret);
      ```

若验证通过，回到程序运行流程， 否则返回错误代码。

> 由于内核接口验证失败的返回是`-EKEYREJECTED`，所以该验证模块也沿用了这一错误代码。

```c
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
```

## 读写ELF文件

由于没有合适的ELF文件读写相关库（尝试了`libelf/gelf`），在充分了解ELF文件格式之后，我们决定手写ELF文件处理程序。

内核空间的一些ELF读取需求示例，用户空间大同小异：

- 读取ELF头：ELF头位于文件的开始，读取`sizeof(Elf64_Ehdr)`长度的字节，之后判断前`SELFMAG`个字节是否与`ELFMAG`相同

  ```c
  elf_ex = kmalloc(sizeof(struct elf64_hdr), GFP_KERNEL);
  kernel_read(file, elf_ex, sizeof(struct elf64_hdr), &offset);
  ```

- 读取程序头：从`e_phoff`位置开始，每一个`sizeof(Elf64_Phdr)`长度的字节都是一个程序头，直到达到数量`e_phnum`

- 读取`load segment`：从第一个程序头开始，查找类型是`PT_LOAD`的程序头，读取从`p_offset`位置开始的`p_filesz`个字节

  ```c
  elf64_phdr = kmalloc(sizeof(Elf64_Phdr), GFP_KERNEL);
  for (i=0;i<elf64_ex->e_phnum;++i) {
      ph_offset = elf64_ex->e_phoff + sizeof(Elf64_Phdr) * i;
      kernel_read(fp, elf64_phdr, sizeof(Elf64_Phdr), &ph_offset);
      if (elf64_phdr->p_type == PT_LOAD)
          break;
  }
  load1_data = vmalloc(elf64_phdr->p_filesz);
  kernel_read(fp, load1_data, elf64_phdr->p_filesz, &elf64_phdr->p_offset);
  ```

- 读取节头：从`e_shoff`位置开始，每一个`sizeof(Elf64_Shdr)`长度的字节都是一个程序头，直到达到数量`e_shnum`

签名程序对ELF文件的编辑：

- 将字符串".signature"写入`.shstrtab`节的尾部，并相应将其`sh_size += sizeof(".signature")`，为了在`readelf`时能够显示新增节的名称

- 将物理位置在`.shstrtab`节之后的节的`sh_offset += sizeof(".signature")`

- 将生成的`signature`写到最后一个节之后

- 将新的节头写入节头表的尾部（通常也是ELF文件尾部）

  - 设置`sh_size`为`signature`的长度
  - 根据签名的类型设置`sh_type`为`SHT_SIG_PKEY`或`SHT_SIG_CERT`
  - 设置`sh_name`为".signature"在`.shstrtab`的位置
  - 设置`sh_offset`为该节在ELF文件中的位置

- 设置ELF头的`e_shoff += sizeof(".signature") + 签名长度`，`e_shnum += 1`

  > 节头表的位置在`.shstrtab`和签名数据之后

ELF文件编辑示意图：

![Elf-layout--en](https://user-images.githubusercontent.com/25382292/220274886-537c937a-f219-4d6e-8fc0-663af706c585.jpg)

> 签名程序可以撤销对ELF文件的签名，将签名的步骤逆向操作即可。

> 因为`load segment`包含了ELF头，签名之后我们不得不改变ELF头的`e_shoff`和`e_shnum`，所以在验证时，需要将ELF头恢复到签名前的状态，也就是将`load segment`恢复到签名前的状态，之后再进行散列，得到的`digest`才会和签名前一致。
>
> 这就需要在验证模块中，散列前设置`e_shoff -= sizeof(".signature") + 签名长度`，`e_shnum -= 1`，之后使用该ELF头替换`load segment`数据的前`sizeof(Elf64_Ehdr)`个字节

# 参考资料

- [1] [Hooking Linux Kernel Functions, Part 2: How to Hook ... - Apriorit](https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2)
- [2] [OpenSSL libraries](https://www.openssl.org/docs/man1.1.1/man3/)
- [3] [Asymmetric Cipher Algorithm Definitions — The Linux Kernel  documentation](https://www.kernel.org/doc/html/v5.3/crypto/api-akcipher.html)
- [4] [Executable and Linkable Format - Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
