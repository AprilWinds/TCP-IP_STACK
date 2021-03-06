#include <stdio.h>
#include <signal.h>
#include "device.h"

#define DEFAULT_IFNAME "wlp0s20f3"


void signal_handler(int sig_num){
    net_device_t* ndev = netdev_get();
    if(ndev)
        netdev_stop_loop(ndev);
}


int main(){
    signal(SIGINT,signal_handler);

    net_device_t* ndev = netdev_init(DEFAULT_IFNAME);
    if(ndev == NULL) return -1;
    netdev_start_loop(ndev);

out:
   netdev_destory(ndev);
   return 0;

}