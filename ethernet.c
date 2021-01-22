#ifndef __ETHERNET_H_
#define __ETHERNET_H_
#include "utils.h"

typedef struct _dev_rx_pkt{
    queue_t node;
    unsigned int seq;
    unsigned int len;
    unsigned char payload[0];
}__attribute__ ((packed)) dev_rxpkt_t;


typedef struct _dev_tx_pkt{
    queue_t node;
    unsigned int seq;
    void* pbuf;
}__attribute__((packed)) dev_txpkt_t;


#endif