#ifndef _DEVICE_H_
#define _DEVICE_H_
#include <pcap/pcap.h>
    

#define MAX_NETWORK_SEGMENT_SIZE       65535
#define PROMISC_ENABLE                 1
#define PROMISC_DISABLE                0
#define TIMEOUT_MS                     512
#define FILTER_BUFFER_SIZE             256
 

typedef struct _net_device{
    pcap_t* pcap_dev;
}net_device_t;

net_device_t*  netdev_init(char* if_name);
void netdev_deinit(net_device_t* ndev);
void netdev_start_loop(net_device_t* ndev);
void netdev_stop_loop(net_device_t* ndev);
net_device_t* netdev_get();

#endif