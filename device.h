#ifndef _DEVICE_H_
#define _DEVICE_H_

#include "utils.h"
#include <pcap/pcap.h>
#include <pthread.h>

#define MAX_NETWORK_SEGMENT_SIZE       65535
#define PROMISC_ENABLE                 1
#define PROMISC_DISABLE                0
#define TIMEOUT_MS                     512
#define FILTER_BUFFER_SIZE             256
 

typedef struct _net_device{
    pcap_t* pcap_dev;
    
    //rx
    pthread_t rx_thread;
    pthread_cond_t rxq_cond;
    pthread_mutex_t rxq_mutex;
    queue_t rxpkt_q;

    //tx
    int tx_sock;
    pthread_t tx_thread;
    pthread_mutex_t txq_mutex;
    pthread_cond_t  txq_cond;
    queue_t txpkt_q;
    int ifindex;
}net_device_t;


net_device_t*  netdev_init(char* if_name);
void netdev_destory(net_device_t* ndev);
void netdev_start_loop(net_device_t* ndev);
void netdev_stop_loop(net_device_t* ndev);
net_device_t* netdev_get();

#endif