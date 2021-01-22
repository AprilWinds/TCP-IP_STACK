#ifndef __COMMON_H_
#define __COMMON_H_

#define IPV4_NETWORK_MASK     0xffffff00
#define ETHERNET_IP           0x0800
#define ETHERNET_ARP          0x0806
#define ETHERNET_ADDR_LEN     6
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(x) (x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5]
 
typedef struct _ethhdr {
    unsigned char dst[ETHERNET_ADDR_LEN];
    unsigned char src[ETHERNET_ADDR_LEN];
    unsigned short type;
} __attribute__((packed)) ethhdr_t;

#define NTOHS(x) ({\
           unsigned short val = (x);\
           unsigned char *b = (unsigned char *)&(val);\
           b[0] << 8 | b[1]; })

#define NTOHL(x) ({\
           unsigned int val = (x);\
           unsigned char *b = (unsigned char *)&(val); \
           b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];  })
                                                          

#define HTONS    NTOHS                                   
#define HTONL    NTOHL                                   



#endif