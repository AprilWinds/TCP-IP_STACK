#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <time.h>s
#include "common.h"
#include "device.h"


static net_device_t* gndev = NULL;
static int terminate_loop;


static void rx_func(void* arg){
    if(arg == NULL) return;
    net_device_t* ndev = (net_device_t*)arg;
    while(!terminate_loop){
        pthread_mutex_lock(&ndev->rxq_mutex);
        if(!queue_empty(&ndev->rxpkt_q)){
            queue_t* q = dequeue(&ndev->rxpkt_q);
        pthread_mutex_unlock(&ndev->rxq_mutex);
        dev_rxpkt_t* rx_pkt = container_of(q,dev_rxpkt_t,node);
        if(rx_pkt != NULL){
            ethhdr_t* eth = (dev_rxpkt_t*)rx_pkt;
            printf("dev rx, ethernet type:%04x ,"MACSTR "-->"MACSTR "\n",NTOHS(eth->type),MAC2STR(eth->src),MAC2STR(eth->dst));
            free(eth);
        }
        }else{
            pthread_cond_wait(&ndev->rxq_cond,&ndev->rxq_mutex);
        }
        pthread_mutex_unlock(&ndev->rxq_mutex);
    }
    printf("[info] Dev rx_func end\n");
    pthread_exit(0);
}

static int dev_rx_init(net_device_t* ndev){    
   
    queue_init(&ndev->rxpkt_q);// 放弃等待直接结束未处理的直接丢弃
    pthread_mutex_init(&ndev->rxq_mutex,NULL);         
    pthread_cond_init(&ndev->rxq_cond,NULL);
    terminate_loop = 0;
    pthread_create(&ndev->rx_thread,NULL,rx_func,(void*)ndev);
    printf("[info] dev_rx init\n");
    return 1;
}

static void dev_rx_destory(net_device_t* ndev){
    if(ndev == NULL) return;
    terminate_loop = 1;
    pthread_cond_signal(&ndev->rxq_cond);   
    pthread_join(ndev->rx_thread,NULL);
    pthread_mutex_destroy(&ndev->rxq_mutex);
    pthread_cond_destroy(&ndev->rxq_cond);
    printf("[info] Dev rx destory\n");
}

static void tx_func(void* arg){
    if(arg == NULL) return;
    net_device_t* ndev = (net_device_t*)arg;
    while (!terminate_loop){
    }
    pthread_exit(0);
    printf("[info] Dev_tx tx_func end\n");
}

static int dev_tx_init(net_device_t* ndev){
    
    queue_init(&ndev->txpkt_q);
    pthread_mutex_init(&ndev->txq_mutex,NULL);
    pthread_cond_init(&ndev->txq_cond,NULL);
    pthread_create(&ndev->tx_thread,NULL,tx_func,(void*)ndev);
    printf("[info] Dev_tx init\n");
    return 1;
}

static void dev_tx_destory(net_device_t* ndev){
    if(ndev == NULL) return;
    terminate_loop = 1;
    pthread_mutex_destroy(&ndev->txq_mutex);
    pthread_cond_destroy(&ndev->txq_cond);
    printf("[info] Dev_tx destory\n");
}

static void  pcap_callback(unsigned char *arg, const struct pcap_pkthdr *pkthdr, 
                             const unsigned char *packet){
    
    if(packet == NULL || arg == NULL) return;
    net_device_t* ndev = (net_device_t*) arg;
    struct tm* t=localtime(&pkthdr->ts.tv_sec);
    printf("%d:%d:%d:%d capture length: %u, pkt length: %u\n",
      t->tm_hour,t->tm_min,t->tm_sec, pkthdr->caplen, pkthdr->len);
    unsigned int alloc_len  = pkthdr->caplen +sizeof(dev_rxpkt_t);
    dev_rxpkt_t* rx_pkt = (dev_rxpkt_t*)malloc(alloc_len);
    printf("[test] %p\n",rx_pkt);
    memset(rx_pkt,0,alloc_len);
    memcpy(rx_pkt->payload,packet,pkthdr->caplen);
    rx_pkt->len = pkthdr->caplen;
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
    if(!dev_rx_init(ndev)) 
        goto out;
    if(!dev_tx_init(ndev))
        goto out;

    return ndev;
out:
    netdev_destory(ndev);
    return NULL;
}


void netdev_destory(net_device_t* ndev){
    if(ndev == NULL) return;
    printf("[info] Network device destory\n");
    if(ndev->pcap_dev != NULL)  
        pcap_close(gndev->pcap_dev);
    dev_rx_destory(ndev);
    dev_tx_destory(ndev);
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
}


net_device_t* netdev_get(){
    return gndev;
}
