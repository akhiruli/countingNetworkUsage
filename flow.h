#ifndef __FLOW_H
#define __FLOW_H
#define X86_CACHE_LINE_SIZE (64)

struct __attribute__((aligned (X86_CACHE_LINE_SIZE))) flow_info{
    unsigned int src_ip;        //
    unsigned int src_netmask;        //
    unsigned int src_port;        //0~2^32
    unsigned int dest_ip;
    unsigned int dest_netmask;
    unsigned int dest_port;
    unsigned int bytes;
    unsigned char proto;        //0: all, 1: tcp, 2: udp
    unsigned rx_fin:1;
    unsigned tx_fin:1;
    unsigned fin:1;
    unsigned activity:1;
    uint32_t seq;            //TCP sequence number
    uint32_t app_seq;
    uint64_t session_key;
};
#endif
