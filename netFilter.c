//#define __KERNEL__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/time.h>
#include "flow.h"
#include "kernel_bytecount_intf.h"

#define  HASH_TABLE_SIZE     1000000
#define  MYGRP               22
//#define  MYPROTO             NETLINK_GENERIC
#define MYPROTO NETLINK_USERSOCK

MODULE_LICENSE("GPL");
    
MODULE_DESCRIPTION("linux-simple-firewall");                                                          
        
MODULE_AUTHOR("Liu Feipeng/roman10");

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])

static struct nf_hook_ops netfilter_ops_in; /* NF_IP_PRE_ROUTING */
static struct nf_hook_ops netfilter_ops_out; /* NF_IP_POST_ROUTING */
//static struct nf_hook_ops netfilter_local_out; /* NF_IP_POST_ROUTING */
static struct timer_list  g_timer;
static struct timer_list g_aging_timer;
//spinlock_t my_lock = SPIN_LOCK_UNLOCKED; /* the lock for the counter */

struct flow_info *flow_table[HASH_TABLE_SIZE];
static struct sock *nl_sk;

__u32 pid = 0;

int ifc_index = -1;
int slotId = -1;
/* Function prototype in <linux/netfilter> */

unsigned int get_hash_index(unsigned int src_ip, unsigned int src_port,
                            unsigned int dest_ip, unsigned int dest_port,
                            unsigned char proto)
{
   unsigned int hash_val = ((size_t)(src_ip + dest_ip) * 59) ^
   ((size_t)(dest_ip)) ^
   ((size_t)(src_port + dest_port) << 16) ^
   ((size_t)(dest_port)) ^
   ((size_t)(proto));
   return (hash_val % HASH_TABLE_SIZE);
}

int get_ifc_index(const char *ifc)
{
   int _index = -1;
   struct net_device *dev;

   read_lock(&dev_base_lock);

   dev = first_net_device(&init_net);
   while (dev) 
   {
      if(strcmp(ifc, dev->name) == 0)
      {
         printk(KERN_INFO "found device [%s], index [%d]\n", dev->name, dev->ifindex);
         _index = dev->ifindex;
         break;
      }
      dev = next_net_device(dev);
   }

   read_unlock(&dev_base_lock);
   return _index;
}

int sendMsgToUserSpace(struct flow_info *flow)
{
    //printk(KERN_INFO "sendMsgToUserSpace\n");                                                         
    //printk(KERN_INFO "Sending multicast. src ip %u, dest_ip %u, src_port %u, dest_port %u bytes %u\n", flow->src_ip, flow->dest_ip, flow->src_port, flow->dest_port, flow->bytes);
    //flow->bytes -= flow->bytes; 
    //return 0;

    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = 0;
    int res;
    
    if(!nl_sk || !flow){
       printk(KERN_ERR "nl_sk is NULL");                                                              
       return -1;
    }                                                                                                 

    if(pid <= 0)
    {
       printk(KERN_ERR "nobody has registered\n");
       return -1;
    }   

    msg_size = sizeof(struct kernel_bytecount);
    skb = nlmsg_new(NLMSG_ALIGN(msg_size + 1), GFP_ATOMIC);                                           
    if (!skb) {
        printk(KERN_ERR "Allocation failure.\n");                                                     
        return -1;                                                                                       
    }                                                                                                 
    
    nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, msg_size + 1, 0);                                          
    NETLINK_CB(skb).dst_group = 0;

    struct kernel_bytecount byte_count;
    byte_count.src_ip = flow->src_ip;
    byte_count.src_port = flow->src_port;
    byte_count.dest_ip  = flow->dest_ip;
    byte_count.dest_port = flow->dest_port;
    byte_count.bytes = flow->bytes;

    memcpy(NLMSG_DATA(nlh), &byte_count, msg_size);                                                          
    
//    printk(KERN_INFO "Sending multicast. src ip %u, dest_ip %u, src_port %u, dest_port %u\n", byte_count.src_ip, byte_count.dest_ip, byte_count.src_port, byte_count.dest_port);
    res = nlmsg_multicast(nl_sk, skb, 0, MYGRP, GFP_ATOMIC);
    //res = nlmsg_unicast(nl_sk, skb, pid);
    if (res < 0)
    {
        printk(KERN_ERR "nlmsg_multicast() error: %d. Will try again later.\n", res);                
        return -1;
    }
    else
    {
        printk(KERN_INFO "Sending multicast. src ip %u, dest_ip %u, src_port %u, dest_port %u bytes %u\n", byte_count.src_ip, byte_count.dest_ip, byte_count.src_port, byte_count.dest_port, byte_count.bytes);
        flow->bytes -= flow->bytes;
    }

    return 0;
}


struct flow_info *create_flow(struct iphdr *ip_header, struct tcphdr *tcp_header, struct sk_buff *skb)
{
    unsigned int src_port = 0;
    unsigned int dest_port = 0;
    struct flow_info *_flow = NULL;
    int rand;

    src_port = (unsigned int)ntohs(tcp_header->source);
    dest_port = (unsigned int)ntohs(tcp_header->dest);
    _flow = (struct flow_info *)kmalloc(sizeof(struct flow_info) + 1, GFP_KERNEL);
    _flow->src_ip = (unsigned int)ip_header->saddr;
    _flow->src_port = src_port;
    _flow->dest_ip = (unsigned int)ip_header->daddr;
    _flow->dest_port = dest_port;
    _flow->proto = ip_header->protocol;
    _flow->bytes = skb->len;
    _flow->rx_fin = 0;
    _flow->tx_fin = 0;
    _flow->fin = 0;
    _flow->app_seq = 1;
    _flow->seq = tcp_header->seq;

    get_random_bytes(&_flow->session_key, sizeof(uint64_t));

    return _flow;
}

/*unsigned int in_hook(unsigned int hooknum,  
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))*/
unsigned int in_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
   if(state && state->in && state->in->ifindex != ifc_index)
      return NF_ACCEPT;

   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct tcphdr *tcp_header;
   /**get src and dest ip addresses**/
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;

   unsigned int src_port = 0;
   unsigned int dest_port = 0;

   struct flow_info *flow = NULL;

   __u32 hash_index = 0;

   if (ip_header->protocol == 6) 
   {
//       tcp_header = (struct tcphdr *)skb_transport_header(skb);
       tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dest_port = (unsigned int)ntohs(tcp_header->dest);

       //char *state = NULL;
       hash_index = get_hash_index(src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
       flow = flow_table[hash_index];

if(dest_port != 80 )
   return NF_ACCEPT;

       if(tcp_header->syn && tcp_header->ack)
       {
          //state = "SYN-ACK";
          if(!flow)
          {
             //printk(KERN_INFO "IN creating FLOW\n");
             struct flow_info *_flow = create_flow(ip_header, tcp_header, skb);
             flow_table[hash_index] = _flow;
             flow = _flow;
          }
          else
             flow->bytes += skb->len;
       }
       else if(tcp_header->fin && tcp_header->ack)
       {
          //state = "FIN-ACK";
          if(flow)
          {
             flow->bytes += skb->len;
             flow->rx_fin = 1;
          }
       }
       else if(tcp_header->syn)
       {
          //state = "SYN";
          if(!flow)
          {
             printk(KERN_INFO "IN creating FLOW\n");
             struct flow_info *_flow = create_flow(ip_header, tcp_header, skb);;
             flow_table[hash_index] = _flow;
             flow = _flow;
          }
          else
          {
             flow->bytes += skb->len;
             if(tcp_header->seq != flow->seq)
             {
                //flow reused case
                struct flow_info *_flow = create_flow(ip_header, tcp_header, skb);
                flow_table[hash_index] = _flow;
                flow = _flow;
             }
          }
   //       printk(KERN_INFO "IN packet info: dest port: %u, hash index %u\n", dest_port, hash_index);
       }
       else if(tcp_header->ack)
       {
          //state = "ACK";    
          if(flow)
          {
             flow->bytes += skb->len; 
             if(flow->rx_fin && flow->tx_fin)
             {
                sendMsgToUserSpace(flow);
                kfree(flow);
                flow_table[hash_index] = NULL;
             }
          }
       }
       else if(tcp_header->psh)
       {
          if(flow)
            flow->bytes += skb->len; 
          //state = "PSH";
       }
       else if(tcp_header->fin)
       {
          if(flow)
            flow->bytes += skb->len; 
          //state = "FIN";
       }
       else if(tcp_header->rst)
       {
          if(flow)
            flow->bytes += skb->len; 
          //state = "RST";
       }

       //printk(KERN_INFO "IN packet info: src ip: %d.%d.%d.%d, src port: %u; dest ip: %d.%d.%d.%d, dest port: %u; proto: %u, state: %s data_len: %u\n, total bytes: %u, hash index: %u",
       //                  NIPQUAD(ip_header->saddr), src_port, NIPQUAD(ip_header->daddr), dest_port, ip_header->protocol, state?state:"NULL", skb->len, flow?flow->bytes:0, hash_index);
   }

   return NF_ACCEPT;
}
/*unsigned int out_hook(unsigned int hooknum,  
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))*/
unsigned int out_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
   if(state && state->out && state->out->ifindex != ifc_index)
      return NF_ACCEPT;

   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct tcphdr *tcp_header;
   /**get src and dest ip addresses**/
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
   unsigned int hash_index = 0;
   struct flow_info *flow = NULL;

   if (ip_header->protocol == 6)
   {
       //tcp_header = (struct tcphdr *)skb_transport_header(skb);
       tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dest_port = (unsigned int)ntohs(tcp_header->dest);

if(src_port != 80 )
   return NF_ACCEPT;

       //char *state;
       //unsigned int hash_index = get_hash_index(src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
       hash_index = get_hash_index(src_ip, dest_port, dest_ip, src_port, ip_header->protocol);
       flow = flow_table[hash_index];

       if(tcp_header->syn && tcp_header->ack)
       {
          //state = "SYN-ACK";
          if(!flow)
          {
             printk(KERN_INFO "OUT creating FLOW\n");
             struct flow_info *_flow = create_flow(ip_header, tcp_header, skb);
             flow_table[hash_index] = _flow;
             flow = _flow;
          }
          else
             flow->bytes += skb->len;
       }
       else if(tcp_header->fin && tcp_header->ack)
       {
          //state = "FIN-ACK";
          if(flow)
          {
             flow->bytes += skb->len;
             flow->tx_fin = 1;
          }
       }
       else if(tcp_header->syn)
       {
          //state = "SYN";
          if(!flow)
          {
             //printk(KERN_INFO "OUT creating FLOW\n");
             struct flow_info *_flow = create_flow(ip_header, tcp_header, skb);
             flow_table[hash_index] = _flow;
             flow = _flow;
          }
          else
             flow->bytes += skb->len;
       }
       else if(tcp_header->ack)
       {
          //state = "ACK";    
          if(flow)
          {
             flow->bytes += skb->len; 
             if(flow->rx_fin && flow->tx_fin)
             {
                sendMsgToUserSpace(flow);
                kfree(flow);
                flow_table[hash_index] = NULL;
             }
          }
       }
       else if(tcp_header->psh)
       {
          //state = "PSH";
          if(flow)
            flow->bytes += skb->len; 
       }
       else if(tcp_header->fin)
       {
          //state = "FIN";
          if(flow)
            flow->bytes += skb->len; 
       }
       else if(tcp_header->rst)
       {
          //state = "RST";
          if(flow)
            flow->bytes += skb->len; 
       }
       //printk(KERN_INFO "OUT packet info: src ip: %d.%d.%d.%d, src port: %u; dest ip: %d.%d.%d.%d, dest port: %u proto: %u, state: %s, data len: %u total bytes: %u, hash index: %u\n",
         //     NIPQUAD(ip_header->saddr), src_port, NIPQUAD(ip_header->daddr), dest_port, ip_header->protocol, state?state:"NULL", skb->len, flow?flow->bytes:0, hash_index);
   }

   return NF_ACCEPT;
}

void timeout_cbk (unsigned long arg)
{
    //printk (KERN_INFO "Called timer \n"); 
    unsigned int i = 0;
    for(;i < HASH_TABLE_SIZE; i++)
    {
       struct flow_info *flow = flow_table[i];
       if(flow)
       {
          //printk(KERN_INFO "BYTE_COUNT %u for src ip:%u: %d.%d.%d.%d, src port: %u; dest ip: %d.%d.%d.%d, dest port: %u\n", flow->bytes, flow->src_ip, NIPQUAD(flow->src_ip), flow->src_port, NIPQUAD(flow->dest_ip), flow->dest_port);
          if(flow->bytes)       
          {
             sendMsgToUserSpace(flow);
             if(flow->activity)
                flow->activity = 0;
             else
             {
                sendMsgToUserSpace(flow);
                kfree(flow);
                flow_table[i] = NULL;
             }
          }
       }
    }

    g_timer.expires = jiffies + 10*HZ;
    add_timer (&g_timer); /* setup the timer again */
}

void agingtimeout_cbk (unsigned long arg)
{
    unsigned int i = 0;
    for(;i < HASH_TABLE_SIZE; i++)
    {
       struct flow_info *flow = flow_table[i];
       if(flow)
       {
          if(flow->activity)
             flow->activity = 0;
          else
          {
             sendMsgToUserSpace(flow);
             kfree(flow);
             flow_table[i] = NULL;
          }
       }
    }

    g_aging_timer.expires = jiffies + 300*HZ;
    add_timer (&g_aging_timer);
}

static void userspace_msg(struct sk_buff *skb)
{
   struct nlmsghdr *nlh = NULL;
   struct kernel_register *ifc_data = NULL;

   nlh=(struct nlmsghdr*)skb->data;
   pid = nlh->nlmsg_pid; /*pid of sending process */

   ifc_data = (struct kernel_register *)nlmsg_data(nlh);

   printk(KERN_INFO "Netlink received ifc:%s pid:%u slotId:%d\n", ifc_data->interface, pid, ifc_data->slot_id);
   
   ifc_index = get_ifc_index(ifc_data->interface);
   slotId = ifc_data->slot_id;
}

long get_session_key(unsigned int src_ip, unsigned int src_port,
                            unsigned int dest_ip, unsigned int dest_port)
{
   struct timespec ts;
   getnstimeofday(&ts);

   long timestamp = ts.tv_sec + ts.tv_nsec;   

   long hash_val = ((long)(src_ip + dest_ip) * 59) ^
   ((long)(dest_ip)) ^
   ((long)(src_port + dest_port) << 16) ^
   ((long)(dest_port)) ^
   ((long)(slotId)) ^
   ((long)(timestamp));

   return hash_val;
}

int init_module()
{
   unsigned long currentTime = jiffies; 
   unsigned long expiryTime = currentTime + 10*HZ; /* HZ gives number of ticks per second */
   unsigned long agingExpTime = currentTime + 300*HZ; /* HZ gives number of ticks per second */
   __u32 i;

   struct netlink_kernel_cfg cfg = {
      .input = userspace_msg,
   };

   nl_sk = netlink_kernel_create(&init_net, MYPROTO, &cfg);
//   nl_sk = netlink_kernel_create(&init_net, MYPROTO, 0,userspace_msg, NULL, THIS_MODULE);
   if (!nl_sk) {
      printk(KERN_ERR"Error creating socket.\n");
      return -10;
   }

   netfilter_ops_in.hook                   =       in_hook;
   netfilter_ops_in.pf                     =       PF_INET;
   netfilter_ops_in.hooknum                =       NF_INET_PRE_ROUTING;
   //netfilter_ops_in.hooknum                =       0;
   netfilter_ops_in.priority               =       NF_IP_PRI_FIRST;

   netfilter_ops_out.hook                  =       out_hook;
   netfilter_ops_out.pf                    =       PF_INET;
   netfilter_ops_out.hooknum               =       NF_INET_POST_ROUTING;
   //netfilter_ops_out.hooknum               =       4;
   netfilter_ops_out.priority              =       NF_IP_PRI_FIRST;

   nf_register_hook(&netfilter_ops_in); /* register NF_IP_PRE_ROUTING hook */
   nf_register_hook(&netfilter_ops_out); /* register NF_IP_POST_ROUTING hook */

   for(i = 0; i < HASH_TABLE_SIZE; i++)
      flow_table[i] = NULL;

   /* pre-defined kernel variable jiffies gives current value of ticks */
   init_timer(&g_timer); 
   g_timer.function = timeout_cbk;
   g_timer.expires = expiryTime;
   g_timer.data = 0;
   printk (KERN_INFO "timer added \n");

#if 0
   add_timer (&g_timer);

   init_timer(&g_aging_timer);
   g_aging_timer.function = agingtimeout_cbk;
   g_aging_timer.expires = agingExpTime;
   g_aging_timer.data = 0;
   add_timer (&g_aging_timer);
#endif

   //ifc_index = get_ifc_index("ens160");
   ifc_index = get_ifc_index("lo");

//testing purpose;
/*   struct timespec ts;
   getnstimeofday(&ts);
   printk(KERN_INFO "timestamp sec(%u) nanosec(%u)\n", ts.tv_sec, ts.tv_nsec);
   int ix = 0;
   for(;ix<=10; ix++)
   {
      printk(KERN_INFO "session KEY %u\n",get_session_key(3397563006, 6550, 3397563006, 80));
   }*/
   return 0;
}

void cleanup_module()
{
   __u32 i;
   netlink_kernel_release(nl_sk);

   nf_unregister_hook(&netfilter_ops_in); /*unregister NF_IP_PRE_ROUTING hook*/
   nf_unregister_hook(&netfilter_ops_out); /*unregister NF_IP_POST_ROUTING hook*/

   for(i = 0;i < HASH_TABLE_SIZE; i++)
   {
      struct flow_info *flow = flow_table[i];
      if(flow)
         kfree(flow);
   }

   del_timer (&g_timer);
//   del_timer (&g_aging_timer);
}
//nip_hdr->check = ip_fast_csum((unsigned char *)nip_hdr, nip_hdr->ihl);
