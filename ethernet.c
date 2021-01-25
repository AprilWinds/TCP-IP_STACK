#include "device.h"
#include "ethernet.h"
#include <errno.h>
#include "common.h"
#include "string.h"

void rx_func(void* arg){
    if(arg == NULL) return;
    net_device_t* ndev = (void*)arg;
    queue_t queue = ndev->rxpkt_q;

    while (1){
        if(!list_empty(&queue)){
            pthread_mutex_lock(&ndev->rxq_mutex);
            dev_rxpkt_t* rx = container_of(dequeue(&queue),dev_rxpkt_t,node);
            pthread_mutex_unlock(&ndev->rxq_mutex);
            ethhdr_t* eth = NULL; 
            if(rx != NULL){
                memset(eth,sizeof(ethhdr_t),0);
                memcpy(eth,rx->payload,rx->len);
                printf("dev rx, ethernet type: %04x, "MACSTR " --> " MACSTR"\n",
                 NTOHS(eth->type), MAC2STR(&eth->src), MAC2STR(eth->dst));
            }
        }
        pthread_cond_wait(&ndev->rx_thread,&ndev->rxq_mutex);
    }
    printf("[info] dev_rx processing end\n");
}

int dev_rx_init(net_device_t* ndev){    
    queue_init(&ndev->rxpkt_q);
    if(pthread_mutex_init(&ndev->rxq_mutex,NULL))
             
    if(pthread_cond_init(&ndev->rxq_cond,NULL))
       
    if(pthread_create(&ndev->rx_thread,NULL,rx_func,(void*)ndev))


    printf("[info] dev_rx init\n");
    return 1;
}
void dev_rx_destory(net_device_t* ndev){
    if(ndev == NULL) return;
    pthread_join(ndev->rx_thread,NULL);
    pthread_mutex_destroy(&ndev->rxq_mutex);
    pthread_cond_destroy(&ndev->rxq_cond);
    printf("[info] dev_rx destory\n");
}

