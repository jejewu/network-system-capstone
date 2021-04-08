#include <iostream>
#include <string>
#include <pcap.h>
#include <stdlib.h> //system


using namespace std;



void wake_bridge(){
    //check whether processor is avaliable or not
    if(system(NULL) == 0){
        cout << "command processor is not avaliable" << endl;
        exit(1);
    }
    // BRGr ip link add br0 type bridge
    // BRGr brctl addif br0 BRGr-eth0
    // BRGr ip link set br0 up
    system("ip link add br0 type bridge");
    system("brctl addif br0 BRGr-eth0");
    system("ip link set br0 up");
}


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

    //select interface
    int interface;
    cout << "Insert a number to select interface" <<endl;
    cin >> interface;

    //move to that interface
    devp = alldevsp;
    for(int i = 0; i < interface; i++){
        devp = devp->next;
    }
    // cout << devp->name << endl;

    //start listening
    cout << "Start listening at $" << devp->name << endl;

    //bridge
    wake_bridge();
    
    //insert expression
    string expression;
    cout << "Insert BPF filiter expression: " << endl;
    cin.ignore();
    getline(cin, expression);
    cout << "filter: " << expression << endl;


    // pcap_open_live()
    // return NULL -> fail
    // snaplen maximum number of bytes to be captured by pcap -> bufsiz
    // promiscuous mode -> 1 to sniff until an error occurs, and if there is an error, store it in the string errbuf
    // timeout 0 -> no time out we should set it
    pcap_t * capture_handle;
    capture_handle = pcap_open_live(devp->name,  BUFSIZ,  1,  1500, errbuf);
    if(capture_handle == NULL){
        cerr << "error in pcap_open_live" <<endl;
        cerr << "error message" << errbuf;
        exit(1);
    }

    // pcap_compile()
    // optimize -> 1 optimize
    // return -1 -> fail
    struct bpf_program fp;		/* The compiled filter expression */
    bpf_u_int32 netmask = 2356215809; //140.113.0.1
    if ( pcap_compile(capture_handle, &fp, expression.c_str(), 1, netmask) == -1 ) {
		cerr << "error in pcap_compile" << expression.c_str();
        cerr << "error message "<< pcap_geterr(capture_handle);
		exit(1);
	 }
    //pcap_setfilter()
    if( pcap_setfilter(capture_handle, &fp) == -1 ) {
        cerr << "error in pcap_setfilter" <<endl;
        cerr << "error message" << pcap_geterr(capture_handle);
		exit(1);
	 }
    //pcap_loop()
    //cnt = -1 infinity read until error happen
    // user set to NULL
    //return value -1 error happen
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