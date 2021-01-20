#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include "init.h"
#include "common.h"
#include "device.h"

static net_device_t* gndev = NULL;
static int terminate_loop;

static void  pcap_callback(unsigned char *arg, const struct pcap_pkthdr *pkthdr, 
                             const unsigned char *packet){
    if(packet == NULL || arg == NULL) return;
    net_device_t* ndev = (net_device_t*) arg;
    
    printf("%ld.%06ld: capture length: %u, pkt length: %u\n",
      pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len);

    unsigned int copy_len = sizeof(dev_rxpkt_t) +pkthdr->caplen;
    dev_rxpkt_t* rx_pkt = (dev_rxpkt_t* )malloc(copy_len);
    if(rx_pkt == NULL) 
        printf("no memory for rx packet, %s (%d)\n",strerror(errno),errno);
    memset(rx_pkt,0,copy_len);
    rx_pkt->len = pkthdr->caplen;
    memcpy(rx_pkt->payload,packet,rx_pkt->len);
   
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

static void  dev_flush_rxpktq(net_device_t *ndev){
    int flush_count = 0;
    dev_rxpkt_t *rxpkt = NULL;
    queue_t *qnode = NULL;
  
    if (ndev == NULL)
          return;
    while(!queue_empty(&ndev->rxpkt_q)) {
        qnode = dequeue(&ndev->rxpkt_q);
        rxpkt = container_of(qnode, dev_rxpkt_t, node);
        free(rxpkt);
        flush_count += 1;
    }
    printf("dev flushed %d packets\n", flush_count);
}

static void  dev_process_rxpkt(net_device_t* ndev,dev_rxpkt_t* rxpkt){
    ethhdr_t *ethpkt = NULL;
    if (ndev == NULL || rxpkt == NULL)
        return;
    ethpkt = (ethhdr_t *)rxpkt->payload;
          printf("dev rx, ethernet type: %04x, "MACSTR " --> " MACSTR"\n",
          NTOHS(ethpkt->type), MAC2STR(ethpkt->src), MAC2STR(ethpkt->dst));
    free(rxpkt);
}

static void* dev_rx_routine(void* args){
    if(args == NULL) goto out;
    net_device_t* ndev = (net_device_t*)args;
    while(terminate_loop==0){
        pthread_mutex_lock(&ndev->rxq_mutex);
        pthread_cond_wait(&ndev->rxq_cond,&ndev->rxq_mutex);
        pthread_mutex_unlock(&ndev->rxq_mutex);
        if(terminate_loop)
            break;
again:  pthread_mutex_lock(&ndev->rxq_mutex);
        if (!queue_empty(&ndev->rxpkt_q)) {
            queue_t* qnode = dequeue(&ndev->rxpkt_q);
            pthread_mutex_unlock(&ndev->rxq_mutex);
            dev_rxpkt_t* rxpkt = container_of(qnode, dev_rxpkt_t, node);
            dev_process_rxpkt(ndev, rxpkt);
            goto again;
          }
        pthread_mutex_unlock(&ndev->rxq_mutex);

        printf("packet received\n");
    }

out:
    printf("Dev rx routine exited\n");
    pthread_exit(0);
}

static int   dev_rx_init(net_device_t* ndev){
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
    queue_init(&ndev->rxpkt_q);
    return 0;
out:
    return -1;
}

static void  dev_rx_deinit(net_device_t* ndev){
    if(ndev == NULL) 
        return;
    printf("Network device RX deinit\n");
    pthread_cond_signal(&ndev->rxq_cond);
    if(pthread_join(ndev->rx_thread,NULL))
        printf("rx thread join failed, %s (%d)\n",strerror(errno),errno);
    
    dev_flush_rxpktq(ndev);

    if (pthread_cond_destroy(&ndev->rxq_cond))
        printf("rxq condition destroy failed, %s (%d)\n",strerror(errno), errno);

    if (pthread_mutex_destroy(&ndev->rxq_mutex))
        printf("rxq mutex destroy failed, %s (%d)\n",strerror(errno), errno);
}


static void dev_flush_rx_pktq(net_device_t* ndev){

}

static void* dev_tx_routine(void* args){
    
}


static int  dev_tx_init(net_device_t* ndev){
    if(ndev == NULL) return -1;
    if(pthread_cond_init(&ndev->txq_cond))
        printf("")
}

static void dev_tx_deinit(net_device_t* ndev){

}













net_device_t* netdev_init(char* if_name){
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
