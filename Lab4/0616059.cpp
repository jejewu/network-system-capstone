#include <iostream>
#include <string>
#include <pcap.h>
#include <stdlib.h> //system
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <iomanip>

using namespace std;

int packet_num = 0;
int tunnel_num = 0;
string src_ip = "140.113.0.1";

pcap_t * capture_handle;
struct bpf_program fp;
string expression = "not src 140.113.0.1";

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

void compile_and_setfilter(string new_expression){
    bpf_u_int32 netmask = 2356215809; //140.113.0.1
    if(expression.length() != 0){
        expression = expression + " and " + new_expression;
    }
    else{
        expression = new_expression;
    }
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
}

void create_tunnel(string remote_ip){
    //check whether processor is avaliable or not
    if(system(NULL) == 0){
        cout << "command processor is not avaliable" << endl;
        exit(1);
    }

    string tunnel_name = "GRETAP" + to_string(tunnel_num++);
    string link_add, link_up, brctl;
    link_add = "ip link add " + tunnel_name + " type gretap remote " + remote_ip + " local " + src_ip;
    link_up = "ip link set " + tunnel_name + " up";
    brctl = "brctl addif br0 " + tunnel_name;
    cout  << link_add << endl;
    system(link_add.c_str());
    system(link_up.c_str());
    system(brctl.c_str());

    string new_expression = "not src " + remote_ip;
    compile_and_setfilter(new_expression);
    
    cout << "Tunnel finish" << endl << endl;
    sleep(2);
}


void cout_mac(unsigned char addr[ETH_ALEN]){
    for(int i=0; i<5; i++)
        cout << setw(2) << setfill('0') << hex << (int)addr[i] << ":";
    cout << setw(2) << setfill('0') << hex << (int)addr[5] << endl;
}

void cout_ethtype(__u16 h_proto){
    // Convert big-endian to little-endian
    h_proto = (h_proto >> 8) | (h_proto << 8);
    cout << (h_proto == ETH_P_IP ? "IPv4" : "unknown") << endl;
}

// struct foo
// {
//   unsigned a:1;  // <- 4 bits wide only
// };

void call_back(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    // args ->  last argument of pcap_loop() user
    // header -> pcap header
    // packet -> entire packet
    // struct foo *aa = (struct foo *)(packet);
    // struct foo b;
    // cout <<endl <<sizeof(b)<<endl;
    // cout << header->caplen << endl;
    cout << "Packet Num [" << dec << packet_num++ << "]" << endl;
    for(int i = 0; i < (header->caplen); i++){
        cout << setw(2)<<setfill('0')<<hex <<(unsigned int)(packet[i])<<" ";
        
        // if( i%2 == 1) cout <<" ";
        if( i%20 == 19)
            cout << endl;
    }
    cout << endl;

    int size_ethernet = sizeof(struct ethhdr);

    struct ethhdr *ethernet = (struct ethhdr *)(packet);
    struct iphdr *ip = (struct iphdr *)(packet + size_ethernet);

    string src_addr(inet_ntoa(*(in_addr*)&(ip->saddr)));
    string dst_addr(inet_ntoa(*(in_addr*)&(ip->daddr)));

    string remote_ip;
    // cout << "Packet Num [" << dec << packet_num++ << "]" << endl;
    cout << "Source MAC: ";
    cout_mac(ethernet->h_source);
    cout << "Destination MAC: ";
    cout_mac(ethernet->h_dest);
    cout << "Ethernet type: ";
    cout_ethtype(ethernet->h_proto);
    cout << "Src IP " << src_addr <<endl;
    cout << "Dst IP " << dst_addr <<endl;
    string next_pro = "unknown";
    if(ip->protocol == 47){
        next_pro = "GRE";
    }
    cout << "Next Layer Protocol: " << next_pro << endl;
    create_tunnel(src_addr);

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
    cout << "filter: ";
    getline(cin, expression);


    // pcap_open_live()
    // return NULL -> fail
    // snaplen maximum number of bytes to be captured by pcap -> bufsiz
    // promiscuous mode -> 1 to sniff until an error occurs, and if there is an error, store it in the string errbuf
    // timeout 0 -> no time out we should set it
    // pcap_t * capture_handle;
    capture_handle = pcap_open_live(devp->name,  BUFSIZ,  1,  1500, errbuf);
    if(capture_handle == NULL){
        cerr << "error in pcap_open_live" <<endl;
        cerr << "error message" << errbuf;
        exit(1);
    }

    // pcap_compile()
    // optimize -> 1 optimize
    // return -1 -> fail
    // struct bpf_program fp;		/* The compiled filter expression */
    // bpf_u_int32 netmask = 2356215809; //140.113.0.1
    // if ( pcap_compile(capture_handle, &fp, expression.c_str(), 1, netmask) == -1 ) {
	// 	cerr << "error in pcap_compile" << expression.c_str();
    //     cerr << "error message "<< pcap_geterr(capture_handle);
	// 	exit(1);
	//  }
    // //pcap_setfilter()
    // if( pcap_setfilter(capture_handle, &fp) == -1 ) {
    //     cerr << "error in pcap_setfilter" <<endl;
    //     cerr << "error message" << pcap_geterr(capture_handle);
	// 	exit(1);
	//  }
    compile_and_setfilter(expression);

    //pcap_loop()
    //cnt = -1 infinity read until error happen
    // user set to NULL
    //return value -1 error happen
    int cnt = -1;
    if( pcap_loop(capture_handle, cnt, call_back, NULL) == -1){
        cerr << "error in pcap_loop" << endl;
        pcap_close(capture_handle);
        exit(1);
    }

    pcap_close(capture_handle);
	return(0);
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