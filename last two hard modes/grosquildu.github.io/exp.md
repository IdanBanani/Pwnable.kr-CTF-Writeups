---
title: Exploit notes
author: gros
layout: post
---

### #IP control

```
- saved rip
- ptrs in got table
- malloc_hook (triggered f.e. with printf with large string), free_hook etc
- fini array
- vtable in _IO_FILE (stdin, stderr...), fe. flush in stdout vtable
- classes vtables
- atexit, onexit
- handler for custom format in printf
```

### #Random stuff

* bugs
    * strings with/without nullbyte

    * buffer overflow

    * format string

    * UAF

    * double free

    * integer overflow
        * arithmetic overflows
        * widthness overflows
        * signedness bugs

    * integer cut (read rax, compare only eax, then use rax)

    * abs(-INT_MIN) == -INT_MIN
        ```
        c = ctypes.c_int32(-2**31)  # -2**63
        return ctypes.c_int32( ((c.value ^ (c.value >> 31)) - (c.value >> 31)) )
        ```

    * types confusion

    * uninitialized memory

    * race conditions

    * softlinks

    * [shared_ptr misuse](https://blog.scrt.ch/2017/01/27/exploiting-a-misused-c-shared-pointer-on-windows-10/): when two different shared_ptrs points to the same object and one of them decrements refcount to 0 -> free -> UAF

    * dangling pointers (i.e. return string("").c_str(), cause string internal buf is destroyed on return)

    * [unsafe/non-reentrant functions in signal handlers](http://lcamtuf.coredump.cx/signals.txt)

    * gethostbyname - no thread safe, may return static data that subsequent calls will overwrite (race condition betweens calls)

    * inet_aton("1.1.1.1 whatever") is valid

    * accidental-deletion-of-a-list-item-while-iterating-over-it bug

* techniques / tricks

    + fmt string bug without stack control:
        ```
        initial stack:
        stack[x   ] == 0xffff5566: 0xffff5576 -> 0xabcd
        stack[x+16] == 0xffff5576: 0xabcd

        we can %x$n and change 0xabcd to write_where, like 0x55555dead:
        stack[x   ] == 0xffff5566: 0xffff5576 -> 0x55555dead
        stack[x+16] == 0xffff5576: 0x55555dead -> 0x0

        and now we can %x+19$n and change value at 0x55555dead to write_what
        ```

    + [fmt string with `%a`](https://ex-origin.github.io/2019/10/08/Balsn-CTF-2019-PWN-writeup/)

    * partial overwrites

    * dynamic resovler (return to dl_resolve)

    * dt_debug traversal: find ptr in dynamic section, _r_debug struct...

    * when stdin and stdout are closed / redirected to stderr:
        * blind exploitation, like leak something in memory byte-by-byte by using infinite loops and connection closing
        * open /dev/pts/X twice
        * change used _IO_FILE->_fileno to stdin/stdout

    * can't controll some register directly with ROP gadgets? Try to control it by jumping to the original code or some libc function (like atoi can control rax)

    * in init func there are nice rop gadgets (sometimes called return to csu - __libc_csu_init):

        ```
        pop rbx,rbp,r12,r13,r14,r15
        mov rdx, r13
        mov rsi, r14
        mov edi, r15
        call [r12+rbx*8]
        ```

    * you can open "/proc/self/mem" on main function address with mode=2 and write there a shellcode

    * [FILE's vtable checks bypass](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)

    + ASLR bypass
        * memory leak (bum, unexpected)
        * [AnC](https://www.vusec.net/projects/anc/)
        * [PREFETCHT0 asm instruction](https://david942j.blogspot.com/2017/03/write-up-0ctf-2017-qual-pwn647-pages.html)

    + scanf with "%d" -> you can send "-" or "+" and the value won't change

    + scanf with large input (not fmt, just send a lot of smthing) calls malloc and free

    + restriced shellcode
        + try to call `read(0, &shellcode, X)` to bypass restrictions (it is easier than writing full restricted shellcode) 
        + [self-modifying](https://lordidiot.github.io/2019-02-03/nullcon-hackim-ctf-2019/#easy-shell)

    + remote `read` may split data into chunks (some exploits may fail because of that)

    * sigreturn ROP

    + stack canary (cookie):
        + SEH on old windows systems (failure in read, before stack_check_fail)
        + overwrite argv[0] on stack, leak data in stack_check_fail (old libc)
        + overwrite global value (`fs:[0x28]`, thread local area or smthing)
        + leak it from stack
            + using environ
                ```python
                environ = libc_base + libc.symbols['__environ']
                offset = 0
                while True:
                    leaked = leak(environ + offset)
                    if leaked == 0x4006c0:
                        cookie = leak(environ + offset - 0x40)
                        break
                    offset -= 8
                ```
            + [using aux vector (AT_RANDOM)](https://www.blackhat.com/docs/eu-14/materials/eu-14-Kedmi-Attacking-The-Linux-PRNG-On-Android-Weaknesses-In-Seeding-Of-Entropic-Pools-And-Low-Boot-Time-Entropy.pdf)
                ```python
                aux = libc_base + _rtld_global_ro->_dl_auxv
                offset = 0
                while True:
                    if leak(aux + offset) == 0x19:
                        cookie = leak(leak(aux + offset + 8))
                    offset += 16
                ```

    + overwrite in libc's rw page -> can overwrite `__libc_at_exit`

    + malloc of large size (>= 0x300000) returns new page that is located just before libc

    + windows heap leak with fwrite of size 1 (https://twitter.com/gamozolabs/status/1207088312273362945?s=19)

    + you ma close half of socket connection with "shutdown"

    + if remote server works as terminal, sending 0x04=EOF, sending 0x02 it responds with ^B (0x01-> ^A), and may be recognised because it sends \r\n (and not \n)


### #Kernel

* get root
    * change current_thread_info->addr_limit
        * can read/write kernel mem via syscalls
    * set current_thread_info->task->cred->uid = 0;
        * after ptr to cred there is `char comm[TASK_COMM_LEN]; /* executable name excluding path` so you can find it by scanning kernel memory
    * patch sys_setresuid syscall code from "0xe3500000" to "0xe3500001" (arm only?)
        that is patch capability check (flip je to jne)
    * disable SMAP/SMEP in CR4 register
    * write to non-writable pages (change "Write Protect" bit in CR0)
    * commit_creds(prepare_kernel_cred(0))
    * some infos
        ```
        struct thread_info current_thread_info is inside task's kernel stack
        i.e. can get it's addr with: and $esp, 0xFFFFE000

        /* https://elixir.bootlin.com/linux/v4.19.6/source/arch/arm/include/asm/thread_info.h#L49 */
        struct thread_info {
         struct task_struct   *task;        /* main task structure */
          struct exec_domain  *exec_domain; /* execution domain */
         __u32               flags;        /* low level flags */
         __u32               status;       /* thread synchronous flags */
         __u32                cpu;          /* current CPU */
         int                  saved_preempt_count;
         mm_segment_t         addr_limit;
         struct restart_block restart_block;
         void __user          *sysenter_return;
         unsigned int         sig_on_uaccess_error:1;
         unsigned int         uaccess_err:1; /* uaccess failed */
        };
        ```

* building
    * build kernel with debug and 9p (host-guest file sharing)
    * create initramfs with busybox
    * create some kernel module
    * run qemu with the kernel and the module
    * to find/replace: path in kernel_stuff.sh, kernel version in all files

    ```docker
    # file: PATH/docker/Dockerfile
    FROM ubuntu:trusty

    RUN apt-get update && apt-get install -y build-essential gcc wget tar

    RUN mkdir -p /home/gros
    WORKDIR /home/gros

    RUN wget https://mirrors.edge.kernel.org/pub/linux/kernel/v3.x/linux-3.7.1.tar.gz
    RUN tar -xf linux-3.7.1.tar.gz
    RUN sudo dpkg --add-architecture i386
    RUN sudo apt-get update && sudo apt-get install -y  gcc-multilib

    WORKDIR /home/gros/linux-3.7.1

    RUN make defconfig 
    # ENV ARCH=i386
    # RUN make i386_defconfig

    RUN options_to_enable="CONFIG_GDB_SCRIPTS CONFIG_KGDB CONFIG_KGDB_SERIAL_CONSOLE CONFIG_DEBUG_INFO CONFIG_NET_9P CONFIG_NET_9P_VIRTIO CONFIG_NET_9P_DEBUG CONFIG_9P_FS CONFIG_9P_FS_POSIX_ACL CONFIG_PCI CONFIG_VIRTIO_PCI CONFIG_PCI_HOST_GENERIC" && \
        for option in $options_to_enable; do sed -i "/[^\s_]$option/d" .config; echo "$option=y" >> .config; done

    RUN make oldconfig
    RUN make -j6

    CMD echo "Done"

    # notes:
    # add "-fno-pie" to Makefile's KBUILD_CFLAGS (new gcc only)
    # rm "defined" strings from kernel/timeconst.pl (new perl only)
    ```

    ```sh
    # file: PATH/kernel_stuff.sh
    #!/bin/bash

    KERNEL_NAME=some_kernel
    BASEDIR="/$KERNEL_NAME/kernel"
    KERNEL_V=3.7.1
    BUILD_PROCS=7

    function do_make_kernel() {
        echo "do_make_kernel"
        cd "$BASEDIR/docker" || exit 1

        echo "    building "
        docker build  -t $KERNEL_NAME . || exit 1
        cd ..

        echo "    creating"
        docker create -ti --name "c_$KERNEL_NAME" "$KERNEL_NAME" bash

        echo "    copy"
        docker cp "c_$KERNEL_NAME":"/home/gros/linux-$KERNEL_V" ../kernel/

        echo "    rm"
        docker rm -f "c_$KERNEL_NAME"
    }

    function do_busybox() {
        echo "do_busybox"
        cd $BASEDIR || exit 1

        if [ ! -d "busybox" ]; then
            echo "Busybox dir doesn't exists"
            if [ ! -f "busybox-snapshot.tar.bz2" ]; then
                echo "Busybox tar doesn't exists"
                wget https://busybox.net/downloads/busybox-snapshot.tar.bz2;
            fi
            tar -xf "busybox-snapshot.tar.bz2";
        elif [ -d "busybox/_install" ]; then
            echo "Busybox already built, _install exists"
            return;
        fi

        cd busybox || exit 1

        make defconfig

        # Settings ---> Build Options ---> Build BusyBox as a static binary (no shared libs) ---> yes
        # make menuconfig

        options_to_enable="CONFIG_STATIC" && \
        for option in $options_to_enable; do sed -i "/[^\s_]$option/d" .config; echo "$option=y" >> .config; done

        make -j $BUILD_PROCS
        make install
    }

    function do_busybox_i386() {
        cd $BASEDIR || exit 1
        cd busybox || exit 1

        TARGET_DIR=_install_i386

        rm -rf $TARGET_DIR
        mkdir -p $TARGET_DIR

        docker pull i386/busybox
        CID=$(docker create i386/busybox)
        docker cp ${CID}:/bin $TARGET_DIR/
        docker cp ${CID}:/usr $TARGET_DIR/
        docker rm ${CID}
        cp $TARGET_DIR/bin/linuxrc $TARGET_DIR/linuxrc
    }

    function do_initramfs() {
        echo "do_initramfs"
        cd $BASEDIR || exit 1

        TARGET_DIR=_install_i386
        # TARGET_DIR=_install_i386

        rm -rf initramfs
        mkdir -p initramfs && cd initramfs
        mkdir -p bin sbin etc proc sys usr/bin usr/sbin
        cp -a ../busybox/$TARGET_DIR/* . || exit 1

        echo '#!/bin/sh

    mount -t proc none /proc
    mount -t sysfs none /sys

    cat <<!
    Boot took $(cut -d' ' -f1 /proc/uptime) seconds
    Welcome to some old linux!
    !

    mkdir /shared
    mount -t 9p -o trans=virtio qemu_host /shared

    /bin/sh
        ' > init

        chmod +x init
        sudo chown libvirt-qemu:gros -R .
        sudo chmod 775 -R .
        find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
    }

    function do_run_qemu() {
        echo "do_run_qemu"
        cd $BASEDIR || exit 1

        qemu-system-i386 \
          -kernel "./linux-$KERNEL_V/arch/x86/boot/bzImage" \
          -nographic \
          -append "console=ttyS0" \
          -initrd ./initramfs.cpio.gz \
          -m 1024 \
          -virtfs local,id=qemu_host,path=./shared,security_model=none,mount_tag=qemu_host \
          -s \
          -monitor telnet:127.0.0.1:55555,server,nowait;
    }

    function do_module() {
        echo "do_module"
        cd $BASEDIR || exit 1

        docker run -v "$BASEDIR/module":/home/gros/module -it "$KERNEL_NAME" /bin/sh -c 'cd /home/gros/module && make'
        cp ./module/*.ko ./shared/
        cp ./module/test ./shared/

        echo "Run in qemu: cp ./shared/test / && insmod /shared/*.ko"
    }

    do_make_kernel;
    do_busybox;
    do_busybox_i386
    do_initramfs;
    do_module;
    do_run_qemu;
    ```

    ```
    # file: PATH/module/Makefile

    # If KERNELRELEASE is defined, we've been invoked from the
    # kernel build system and can use its language.
    ifneq ($(KERNELRELEASE),)
            obj-m := softmmu_test.o
    # Otherwise we were called directly from the command
    # line; invoke the kernel build system.
    else
            KERNELDIR ?= ../linux-3.7.1
            BUILDDIR  ?= ../linux-3.7.1
            PWD := $(shell pwd)
    default:
        $(MAKE) -C $(KERNELDIR) M=$(PWD) modules

    .PHONY: clean
    clean:
        rm Module.symvers modules.order *.ko *.o
    endif
    ```

* debugging
    ```
    $ gdb ./linux-3.7.1/vmlinux
    (gdb) target remote :1234
    (gdb) hbreak start_kernel
    (gdb) c
    (gdb) lx-dmesg

    check PAE support (bit 5 of cr4 register)
    in QEMU: CTRL+A, then c
        (qemu) info registers
    ```

* QEMU
    * if there is no shared dict nor networking in the qemu, sploits needs to be
    encoded and manually copied. To keep exp size small, compile it with `-fno-builtin -static -nostdlib` and [raw_sploit.h](/assets/other/raw_sploit.h) (replace `main` with `_start`).

### #Heap notes
```
Arena - contiguous region of memory (132 KB), one arena may have many heaps 
Heap - single contiguous memory region holding (coalesceable) malloc_chunks.
    It is allocated with mmap() and always starts at an address aligned to HEAP_MAX_SIZE.
    One heap is in exactly one arena.

For 32 bit systems:
     Max numbers of arenas = 2 * number of cores.
     SIZE_SZ = 4
For 64 bit systems:
     Max numbers of arenas = 8 * number of cores.
     SIZE_SZ = 8

CHUNKS
------------------------
struct malloc_chunk {
    INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if P == 0).  */
    INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. 3LSB: N,M,P*/
    /* A(NON_MAIN_ARENA), M(IS_MMAPPED), P(PREV_INUSE) */

    struct malloc_chunk* fd;         /* double links -- used only if free. */
    struct malloc_chunk* bk;

    /* Only used for large blocks: pointer to next larger size.  */
    struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
    struct malloc_chunk* bk_nextsize;
};

taken from malloc.c:

used chunk
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             User data starts here...                          .
        .                                                               .
        .             (malloc_usable_size() bytes)                      .
        .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             (size of chunk, but used for application data)    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|1|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


free chunk
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Forward pointer to next chunk in list             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Back pointer to previous chunk in list            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Unused space (may be 0 bytes long)                .
        .                                                               .
        .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|0|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


A bit - set if chunk belongs to thread arena
N bit - set if chunk was mapped (other bits are ignored then)
P bit - set if previous chunk is in use, otherwise previous chunk size is correct


BINS
------------------------
128 bins total
64 bins of size       8
32 bins of size      64
16 bins of size     512
 8 bins of size    4096
 4 bins of size   32768
 2 bins of size  262144
 1 bin  of size what's left


not existing bin(1)
unsorted bin(1):
* works as queue for chunks > fastbins
* chunk get in on free or consolidation
* chunk get out on malloc 

fastbins(10):
* below 80 * SIZE_SZ / 4
* bins of sizes 16-80, +8 each
* no coalescing (only in bulk)
* single linked
* 0x30-0x38 are all rounded to 0x40 on x64
    ```
    idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
    idx 1   bytes 25..40 or 13..20
    idx 2   bytes 41..56 or 21..28
    ```

smallbin(62)
* less than 512
* from 16, +8 each
* coalescing

large bins(63)
* coalescing
* ordered


HOUSES
------------------------
The House of Prime: Requires two free's of chunks containing attacker controlled size fields, followed by a call to malloc.

The House of Mind: Requires the manipulation of the program into repeatedly allocating new memory.

The House of Force: Requires that we can overwrite the top chunk, that there is one malloc call with a user controllable size, and finally requires another call to malloc.

The House of Lore: Again not applicable to our example program.

The House of Spirit: One assumption is that the attacker controls a pointer given to free, so again this technique cannot be used.

The House of Chaos: This isn't actually a technique, just a section in the article :)
------------------------



FASTBIN
------------------------
* abusing the fastbin freelist (two times same value in fastbins list):
    + require:
        + double-free on chunk (fastbin size)
        + variable near write_where with value close to fastbin size 

    + malloc two chunks (same size, say 0x40)
    + free chunk1, chunk2, chunk1 (double free vuln);   # now fastbin list is HEAD->chunk1->chunk2->chunk1
    + d = malloc(size); malloc(size);                   # now the list is HEAD->chunk1 and we control content (fd, bk) of chunk1
    + write_where = 0x40                                # (or semething near fastbin size)
    + *d = &write_where - SIZE_SZ; 
    + malloc(size); *ptr = malloc(size);                # ptr is  &write_where + SIZE_SZ
    + fake chunk on stack must be in correct fastbin, othwerwise you will get "malloc(): memory corruption (fast)"

        that means: (write_where>>4)-2 must be equal to fastbin index(idx) (counting from 0)
        that means: write_where == 0x40 -> previous mallocs were with same size

        fastbins:
        32:  0x1ce4000 ◂— idx==0x0
        48:  0x0
        64:  0x40 <-- write_where==0x40, so it must be: idx==2 (2 == 0x40>>4 - 2)
        80:  0x0
        96:  0x0
        112: 0x0
        128: 0x0


UNLINK
------------------------
* unsafe unlink
    + require:
        + free on corrupted chunk (overwritten prev_size + one bit)
        + pointer to chunk at know position

    chunk0(smallbin_size)
     ______
    |prev_size                                      fake_chunk inside chunk0
    |size                                            ______ 
    |fd                                             |prev_size == 0
    |bk                                             |size == 0
    |fd_nextsize = &chunk0_ptr - 3*SIZE_SZ          |fd: fake_chunk->fd->bk == fake_chunk
    |bk_nextsize = &chunk0_ptr - 2*SIZE_SZ          |bk: fake_chunk->bk->fd == fake_chunk
    |__________

    chunk1(smallbin_size) <- overflow
     _________
    |prev_size = smallbin_size (normally it would be smallbin_size+2*SIZE_SZ, but now it points to fake_chunk)
    |size &= ~1 (mark chunk0 as free, do not change size value except LSB)
    |fd
    |bk
    |________

    + malloc two chunks of size smallbin_size (NOT fastbin, >=0x80)
    + setup fake chunk
    + overflow in chunk1 header
    + now free chunk1, so that consolidate backward will unlink fake_chunk overwriting chunk0_ptr (now it points to fake_chunk->fd so &chunk0_ptr - 3*SIZE_SZ)
    + chunk0_ptr[3] = write_where
    + now chunk0_ptr points to write_where
    + chunk0_ptr[0] = write_what


HOUSE of SPIRIT
------------------------
* House of Spirit (free overwritten pointer)
    + require:
        + pointer to controlled memory
        + free on that pointer
        + malloc of fastbin size

    fake_chunk0
     ________
    |prev_size
    |size = fastbin_size (so next chunk is fake_chunk1), M and P bits must be zero
    |fd
    |bk
    |fd_nextsize
    |bk_nextsize
    |________

    fake_chunk1
     ________
    |prev_size
    |size = 0x2240 (above 2*SIZE_SZ, below av->system_mem (128kb by default for the main arena))
    |fd
    |bk
    |fd_nextsize
    |bk_nextsize
    |________

    + malloc whatever to setup heap
    + make two fake chunks
    + overwrite some pointer with &fake_chunk0+2*SIZE_SZ
    + free it, overwritten pointer will be in fastbins
    + malloc of size fastbin_size (or something near) will return &fake_chunk0[2]


HOUSE of FORCE
------------------------
* House of Force (overwrite top chunk's size field)
    + require:
        + known address of top chunk
        + overwritte top chunk's size
        + malloc of arbitrary size
        
    + set top chunk's size to -1 (0xffffffff or something big)
    + compute evil_size = write_where - sizeof(char *)*4 - top_chunk_address (top_chunk_address == prev_size)
    + be carefull with signed evil_size
    + malloc(evil_size) (it will return top_chunk_address+2*sizeof(char *) and set new top_chunk_address to write_where-2*sizeof(char *))
    + malloc(whatever) (it will return write_where)
    + profit
```

### #glibc
```
cat makefile
GLIBC = /path/glibc_versions/2.25
CC = gcc

.PHONY: all
all: test

test: test.c
	${CC} \
	-Wl,-rpath=${GLIBC}:\
	${GLIBC}/math:\
	${GLIBC}/elf:\
	${GLIBC}/dlfcn:\
	${GLIBC}/nss:\
	${GLIBC}/nis:\
	${GLIBC}/rt:\
	${GLIBC}/resolv:\
	${GLIBC}/crypt:\
	${GLIBC}/nptl_db:\
	${GLIBC}/nptl:\
	-Wl,--dynamic-linker=${GLIBC}/elf/ld.so \
	-o test test.c

clean:
	rm -f test test.o
----------

# compile
gcc -Wl,-rpath=${GLIBC}:${GLIBC}/math:${GLIBC}/elf:${GLIBC}/dlfcn:${GLIBC}/nss:${GLIBC}/nis:${GLIBC}/rt:${GLIBC}/resolv:${GLIBC}/crypt:${GLIBC}/nptl:${GLIBC}/nptl_db:-Wl,--dynamic-linker=${GLIBC}/elf/ld.so -o test test.c

# run
LD_PRELOAD="$GLIBC/libc.so:$GLIBC/elf/ld.so:$GLIBC/nptl/libpthread.so" ./test

# gdb ./test
# set environment LD_PRELOAD=/path/glibc_versions/2.25/libc.so:/path/glibc_versions/2.25/elf/ld.so:/path/glibc_versions/2.25/nptl/libpthread.so
# set auto-load safe-path /path/glibc_versions/2.25/nptl_db/
# set libthread-db-search-path /path/glibc_versions/2.25/nptl_db/

# target record-btrace -> race conditions debugging

# patch ld in binary
patchelf --set-interpreter `pwd`/ld.so.2 --set-rpath `pwd` binary
```

### #windows
WinDbg <-> IDA addressation:
* in WinDbg: !address, and find EndAddr+1 (540000)
* in IDA: Edit>Segments>Rebase program and write there above val
