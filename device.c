#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

#include "init.h"
#include "common.h"
#include "device.h"

static net_device_t* gndev = NULL;
static int terminate_loop;

static void pcap_callback(unsigned char *arg, const struct pcap_pkthdr *pkthdr, 
                             const unsigned char *packet){
    if(packet == NULL) return;
    ethhdr_t* ethpkt = (ethhdr_t *)packet;
    net_device_t* ndev = (net_device_t*) arg;
    printf("%ld.%06u: capture length: %u, pkt length: %u, ethernet type: %04x, "MACSTR " --> " MACSTR"\n",
    pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len,
    NTOHS(ethpkt->type), MAC2STR(ethpkt->src), MAC2STR(ethpkt->dst));
    pthread_cond_signal(&ndev->rxq_cond);
}


static void init_packet_filter(char* filter, int size){
    if(filter == NULL || size == 0){
        printf("Null packet filter: %p or Size: %u\n",
                        filter, size);
        return;
    }
    snprintf(filter,FILTER_BUFFER_SIZE,"ether proto 0x%04x or ether proto 0x%04x",
                    ETHERNET_IP,ETHERNET_ARP);
    printf("filter: %s\n",filter);


}

static void* dev_rx_routine(void* args){
    if(args == NULL) goto out;
    net_device_t* ndev = (net_device_t*)args;
    while(!terminate_loop){
        pthread_mutex_lock(&ndev->rxq_mutex);
        pthread_cond_wait(&ndev->rxq_cond,&ndev->rxq_mutex);
        pthread_mutex_unlock(&ndev->rxq_mutex);
        if(terminate_loop)
            break;
        printf("packet received\n");
    }

out:
    printf("Dev rx routine exited\n");
    pthread_exit(0);
}

static int dev_rx_init(net_device_t* ndev){
    if(ndev == NULL) return -1;
    printf("Network device RX init \n");

    if(pthread_cond_init(&ndev->rxq_cond,NULL)){
        printf("Failed to init rxq condition, %s (%d)\n",strerror(errno),errno);
        goto out;
    }
    if(pthread_mutex_init(&ndev->rxq_mutex,NULL)){
        printf("Failed to init rxq mutex, %s (%d)\n",strerror(errno),errno);
        goto out;
    }
    terminate_loop = 0;
    if(pthread_create(&ndev->rx_thread,NULL,dev_rx_routine,(void*)ndev))
        printf("Failed to create rxq thread, %s (%d)\n",strerror(errno),errno);
    return 0;
out:
    return -1;
}

static void dev_rx_deinit(net_device_t* ndev){
    if(ndev == NULL) 
        return;
    printf("Network device RX deinit\n");
    pthread_cond_signal(&ndev->rxq_cond);
    if(pthread_join(ndev->rx_thread,NULL))
        printf("rx thread join failed, %s (%d)\n",strerror(errno),errno);

    if (pthread_cond_destroy(&ndev->rxq_cond))
        printf("rxq condition destroy failed, %s (%d)\n",strerror(errno), errno);

    if (pthread_mutex_destroy(&ndev->rxq_mutex))
        printf("rxq mutex destroy failed, %s (%d)\n",strerror(errno), errno);
}


net_device_t*  netdev_init(char* if_name){
    char pcap_packet_filter[FILTER_BUFFER_SIZE];
    char err_buf[PCAP_BUF_SIZE];
    struct bpf_program filter_code;
    net_device_t* ndev =(net_device_t*)malloc(sizeof(net_device_t));
    if(ndev == NULL){
        printf("no memory for net device, %s(%d)\n",strerror(errno),errno);
        return NULL;
    }
    gndev = ndev;
    
    printf("Network device init\n");
  
    ndev->pcap_dev = pcap_open_live(DEFAULT_IFNAME,
          MAX_NETWORK_SEGMENT_SIZE, PROMISC_ENABLE, TIMEOUT_MS, err_buf);
    if (ndev->pcap_dev == NULL) {
        printf("pcap_open_live failed, %s (%d)\n",
                         strerror(errno), errno);
      goto out;
    }
    
    memset(pcap_packet_filter, 0, FILTER_BUFFER_SIZE);
    init_packet_filter(pcap_packet_filter, FILTER_BUFFER_SIZE);
    if (pcap_compile(ndev->pcap_dev, &filter_code,
                 pcap_packet_filter, 1, IPV4_NETWORK_MASK) < 0) {
        pcap_perror(ndev->pcap_dev, "pcap_compile");
        goto out;
    }
    
    if (pcap_setfilter(ndev->pcap_dev, &filter_code) < 0) {
        pcap_perror(ndev->pcap_dev, "pcap_setfilter");
        goto out;
    }
    if(dev_rx_init(ndev))
        goto out;
    return ndev;
out:
    netdev_deinit(ndev);
    return NULL;
}


void netdev_deinit(net_device_t* ndev){
    if(ndev == NULL) return;
    printf("Network device failed\n");
    if(ndev->pcap_dev)  
        pcap_close(gndev->pcap_dev);
    free(ndev);
    dev_rx_deinit(ndev);
    gndev = NULL;
}


void netdev_start_loop(net_device_t* ndev){
    if(ndev==NULL ||ndev->pcap_dev == NULL) 
        return;
    pcap_loop(gndev->pcap_dev,-1,pcap_callback,(void*)ndev);
}


void netdev_stop_loop(net_device_t* ndev){
    if(ndev == NULL || ndev->pcap_dev == NULL)
        return;
    pcap_breakloop(ndev->pcap_dev);
    terminate_loop = 1;
}


net_device_t* netdev_get(){
    return gndev;
}



