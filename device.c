#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

#include "init.h"
#include "common.h"
#include "device.h"

static net_device_t* gndev = NULL;

static void pcap_callback(unsigned char *arg, const struct pcap_pkthdr *pkthdr, 
                             const unsigned char *packet){
    if(packet == NULL) return;
    ethhdr_t* ethpkt = (ethhdr_t *)packet;

    printf("%ld.%06u: capture length: %u, pkt length: %u, ethernet type: %04x, "MACSTR " --> " MACSTR"\n",
    pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len,
    NTOHS(ethpkt->type), MAC2STR(ethpkt->src), MAC2STR(ethpkt->dst));
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
    gndev = NULL;
}


void netdev_start_loop(net_device_t* ndev){
    if(ndev==NULL ||ndev->pcap_dev == NULL) 
        return;
    pcap_loop(gndev->pcap_dev,-1,pcap_callback,NULL);
}


void netdev_stop_loop(net_device_t* ndev){
    if(ndev == NULL || ndev->pcap_dev == NULL)
        return;
    pcap_breakloop(ndev->pcap_dev);
}


net_device_t* netdev_get(){
    return gndev;
}



