#include <iostream>
#include <pcap.h>


using namespace std;



// void create_tunnle(){

// }


int main(){

    pcap_if_t *alldevsp, *devp; 
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevsp, errbuf) != 0){
        cerr << "error" << endl;
        exit(1);
    }
    
    //list all device
    int number = 0; //count number of device
    for(devp = alldevsp; devp != NULL; devp=devp->next){
        cout << number << " Name: " << devp->name << endl;
        number++;
    }

}

/*
BRGr ip link add GRETAP type gretap remote 140.114.0.1 local 140.113.0.1
BRGr ip link add GRETAP type gretap remote 140.115.0.1 local 140.113.0.1
BRGr ip link set GRETAP up

BRGr ip link add br0 type bridge
BRGr brctl addif br0 BRGr-eth0
BRGr brctl addif br0 GRETAP
BRGr ip link set br0 up
*/