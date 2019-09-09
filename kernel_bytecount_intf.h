#ifndef _H_KERNEL_BYTE_COUNT_
#define _H_KERNEL_BYTE_COUNT_
#define INTERFACE_LEN  32
#define X86_CACHE_LINE_SIZE (64)

struct __attribute__((aligned (X86_CACHE_LINE_SIZE))) kernel_bytecount {
    unsigned int   src_ip;        //
    unsigned int   src_port;        //0~2^32
    unsigned int   dest_ip;
    unsigned int   dest_port;
    unsigned int   bytes;
    unsigned char  proto;        //0: all, 1: tcp, 2: udp
};

struct __attribute__((aligned (X86_CACHE_LINE_SIZE))) kernel_register {
    char      interface[INTERFACE_LEN];
    int       slot_id;
};
#endif
