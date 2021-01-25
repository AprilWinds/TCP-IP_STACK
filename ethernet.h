#ifndef _ETHERNET_H_
#define _ETHERNET_H_
#include "utils.h"
#include  "device.h"

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


int dev_rx_init(net_device_t* ndev);
void dev_rx_destory(net_device_t* ndev);

int dev_tx_init(net_device_t* ndev);
void dev_tx_destory(net_device_t* ndev);

#endif