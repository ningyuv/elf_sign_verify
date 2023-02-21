KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += elf_verify.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
