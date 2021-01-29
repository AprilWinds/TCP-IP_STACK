#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

#include "common.h"
#include "device.h"


static net_device_t* gndev = NULL;
static int terminate_loop;


static void rx_func(void* arg){
    if(arg == NULL) return;
    net_device_t* ndev = (void*)arg;

    while (1){
        pthread_mutex_lock(&ndev->rxq_mutex);
        pthread_cond_wait(&ndev->rxq_cond,&ndev->rxq_mutex);
        if(!queue_empty(&ndev->rxpkt_q)){
            dev_rxpkt_t* rx_pkt= container_of(dequeue(&ndev->rxpkt_q),dev_rxpkt_t,node);
            pthread_mutex_unlock(&ndev->rxq_mutex);
            ethhdr_t* eth = NULL; 
            if(rx_pkt != NULL){
                eth = (ethhdr_t*)rx_pkt->payload;
                printf("dev rx, ethernet type: %04x, "MACSTR " --> " MACSTR"\n",
                 NTOHS(eth->type), MAC2STR(&eth->src), MAC2STR(eth->dst));
                free(rx_pkt);
            }   
        }
        pthread_mutex_unlock(&ndev->rxq_mutex);
    
    }
    printf("[info] dev_rx processing end\n");
}
static int dev_rx_init(net_device_t* ndev){    
    queue_init(&ndev->rxpkt_q);
    pthread_mutex_init(&ndev->rxq_mutex,NULL);         
    pthread_cond_init(&ndev->rxq_cond,NULL);
    pthread_create(&ndev->rx_thread,NULL,rx_func,(void*)ndev);

    printf("[info] dev_rx init\n");
    return 1;
}
static void dev_rx_destory(net_device_t* ndev){
    if(ndev == NULL) return;
    pthread_join(ndev->rx_thread,NULL);
    pthread_mutex_destroy(&ndev->rxq_mutex);
    pthread_cond_destroy(&ndev->rxq_cond);
    printf("[info] dev_rx destory\n");
}




static void  pcap_callback(unsigned char *arg, const struct pcap_pkthdr *pkthdr, 
                             const unsigned char *packet){
    
    if(packet == NULL || arg == NULL) return;
    net_device_t* ndev = (net_device_t*) arg;

    printf("%ld.%06ld: capture length: %u, pkt length: %u\n",
      pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len);
    dev_rxpkt_t* rx_pkt = (dev_rxpkt_t*)malloc(pkthdr->caplen+sizeof(dev_rxpkt_t));
    memset(rx_pkt,0,sizeof(dev_rxpkt_t)+pkthdr->caplen);
    memcpy(rx_pkt->payload,packet,pkthdr->caplen);
   
    pthread_mutex_lock(&ndev->rxq_mutex);
    enqueue(&ndev->rxpkt_q,&rx_pkt->node);
    pthread_mutex_unlock(&ndev->rxq_mutex);

    pthread_cond_signal(&ndev->rxq_cond);
}


static void  init_packet_filter(char* filter, int size){
    if(filter == NULL || size == 0){
        printf("Null packet filter: %p or Size: %u\n",
                        filter, size);
        return;
    }
    snprintf(filter,FILTER_BUFFER_SIZE,"ether proto 0x%04x or ether proto 0x%04x",
                    ETHERNET_IP,ETHERNET_ARP);
    printf("filter: %s\n",filter);

}


net_device_t* netdev_init(char* if_name){
    char pcap_packet_filter[FILTER_BUFFER_SIZE];
    char err_buf[PCAP_BUF_SIZE];
    struct bpf_program filter_code;
    net_device_t* ndev =(net_device_t*)malloc(sizeof(net_device_t));
    if(ndev == NULL){
        printf("[error] no memory for net device, %s\n",strerror(errno));
        return NULL;
    }
    gndev = ndev;
    
    printf("[info] Network device init\n");
  
    ndev->pcap_dev = pcap_open_live(if_name,
          MAX_NETWORK_SEGMENT_SIZE, PROMISC_ENABLE, TIMEOUT_MS, err_buf);
    if (ndev->pcap_dev == NULL) {
        printf("[error] pcap_open_live failed, %s\n",strerror(errno));
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
    dev_rx_init(ndev);

    return ndev;
out:
    netdev_destory(ndev);
    dev_rx_destory(ndev);
    return NULL;
}


void netdev_destory(net_device_t* ndev){
    if(ndev == NULL) return;
    printf("[info] Network device destory\n");
    if(ndev->pcap_dev)  
        pcap_close(gndev->pcap_dev);
    free(ndev);
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
