/*Return codes according to linux kernel/eBPF*/
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/*Protocol types according to the standard*/
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

/*Session identifier*/
struct session_key {
    __be32 saddr;                                   //IP source address
    __be32 daddr;                                   //IP dest address
    __be16 sport;                                   //Source port
    __be16 dport;                                   //Dest port
} __attribute__((packed));

/*Ethernet Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h (slightly different)*/
struct eth_hdr {
    __be64 dst: 48;
    __be64 src: 48;
    __be16 proto;
} __attribute__((packed));

/*Ip Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip.h */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
        ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
    /*The options start here. */
} __attribute__((packed));

/*TCP Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h */
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

BPF_PERF_OUTPUT(skb_events);
BPF_TABLE("lru_hash", struct session_key, uint8_t, HTTP_SESSIONS, N_SESSIONS);

int handle_ingress(struct __sk_buff *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    
   /*Parsing L2*/
    struct eth_hdr *ethernet = data;
    if (data + sizeof(*ethernet) > data_end)
        return TC_ACT_OK;
    
    if (ethernet->proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    /*Parsing L3*/
    struct iphdr *ip = data + sizeof(struct eth_hdr);
    if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
        return TC_ACT_OK;
    if ((int) ip->version != 4)
        return TC_ACT_OK;
    
    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    if(SERVICE_IP != -1 && ip->daddr != SERVICE_IP) {
        return TC_ACT_OK;
    }

    /*Calculating ip header length
     * value to multiply by 4 (SHL 2)
     *e.g. ip->ihl = 5 ; TCP Header starts at = 5 x 4 byte = 20 byte */
    uint8_t ip_header_len = ip->ihl << 2;

    struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
    if ((void *) tcp + sizeof(*tcp) > data_end)
        return TC_ACT_OK;
      
    //http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
    //minimum length of http request is always geater than 7 bytes
    //avoid invalid access memory
    //include empty payload

    uint8_t tcp_header_len = tcp->doff << 2; //SHL 2 -> *4 multiply
    uint32_t payload_length = bpf_htons(ip->tot_len) - ip_header_len - tcp_header_len;

    if(payload_length < 7) {
        return TC_ACT_OK;
    }

    uint32_t payload_offset = sizeof(struct eth_hdr) + ip_header_len + tcp_header_len;
    uint8_t payload[7];
    for (int i = payload_offset, j=0 ; j < 7 ; i++, j++) {
        payload[j] = load_byte(ctx , i);
    }

    bpf_trace_printk("Ingress %u %u %u\n", payload[0], payload[1], payload[2]);

    //Looking only for requests
    if (((payload[0] == 'G') && (payload[1] == 'E') && (payload[2] == 'T')) || 
        ((payload[0] == 'P') && (payload[1] == 'O') && (payload[2] == 'S') && (payload[3] == 'T')) ||
        ((payload[0] == 'P') && (payload[1] == 'U') && (payload[2] == 'T')) ||
        ((payload[0] == 'D') && (payload[1] == 'E') && (payload[2] == 'L') && (payload[3] == 'E') && (payload[4] == 'T') && (payload[5] == 'E')) ||
        ((payload[0] == 'H') && (payload[1] == 'E') && (payload[2] == 'A') && (payload[3] == 'D'))) {
        u32 ingress_magic = 0xfaceb00c;
        struct session_key key = {.saddr=ip->saddr, .daddr=ip->daddr, .sport=tcp->source, .dport=tcp->dest};
        uint8_t val = 1;
        HTTP_SESSIONS.update(&key, &val);
        skb_events.perf_submit_skb(ctx, ctx->len, &ingress_magic, sizeof(ingress_magic));
    }

    return TC_ACT_OK;
}

int handle_egress(struct __sk_buff *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    
   /*Parsing L2*/
    struct eth_hdr *ethernet = data;
    if (data + sizeof(*ethernet) > data_end)
        return TC_ACT_OK;
    
    if (ethernet->proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    /*Parsing L3*/
    struct iphdr *ip = data + sizeof(struct eth_hdr);
    if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
        return TC_ACT_OK;
    if ((int) ip->version != 4)
        return TC_ACT_OK;
    
    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    if(SERVICE_IP != -1 && ip->saddr != SERVICE_IP) {
        return TC_ACT_OK;
    }

    uint8_t ip_header_len = ip->ihl << 2;

    struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
    if ((void *) tcp + sizeof(*tcp) > data_end)
        return TC_ACT_OK;
    
    struct session_key key = {.saddr=ip->daddr, .daddr=ip->saddr, .sport=tcp->dest, .dport=tcp->source};
    uint8_t *val = HTTP_SESSIONS.lookup(&key);
    
    // Looking for packets belonging to an already monitored session
    if (val != NULL) {
        bpf_trace_printk("Egress\n");
        u32 egress_magic = 0xfaceb00d;
        skb_events.perf_submit_skb(ctx, ctx->len, &egress_magic, sizeof(egress_magic));
    }

    return TC_ACT_OK;
}