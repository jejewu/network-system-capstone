#include <iostream>
#include <iomanip>
#include <string>
#include <map>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include <pcap.h>

using namespace std;
int packet_num = 1;
int tunnel_num = 1;
map<string, string> gres = {};

void create_brg(char *name){
    string s_name(name);
    string link_add = "ip link add br0 type bridge";
    string brctl = "brctl addif br0 BRGr-eth0";
    string link_up = "ip link set br0 up";

    system(link_add.c_str());
    system(link_up.c_str());
    system(brctl.c_str());
}

void cout_mac(unsigned char addr[ETH_ALEN]){
    for(int i=0; i<5; i++)
        cout << setw(2) << setfill('0') << hex << (int)addr[i] << ":";
    cout << setw(2) << setfill('0') << hex << (int)addr[5] << endl;
}

void cout_ethtype(__u16 h_proto){
    // Convert big-endian to little-endian
    h_proto = (h_proto >> 8) | (h_proto << 8);
    cout << (h_proto == ETH_P_IP ? "IPv4" : "???") << endl;
}

void create_gre(string saddr, string daddr){
    if(gres.find(saddr) != gres.end())
        return;
    string int_name = "GRETAP" + to_string(tunnel_num ++);

    string link_add = "ip link add " + int_name + " type gretap remote " + saddr + " local " + daddr;
    string link_restart = "ip link set " + int_name + " down; ip link set " + int_name + " up";
    string brctl = "brctl addif br0 " + int_name;

    system(link_add.c_str());
    system(link_restart.c_str());
    system(brctl.c_str());
    gres[saddr] = int_name;

    cout << link_add << endl << link_restart << endl << brctl << endl << endl;
}

static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet){
    int size_ethernet = sizeof(struct ethhdr);

    struct ethhdr *ethernet = (struct ethhdr *)(packet);
    struct iphdr *ip = (struct iphdr *)(packet + size_ethernet);

    string saddr(inet_ntoa(*(in_addr*)&(ip->saddr)));
    string daddr(inet_ntoa(*(in_addr*)&(ip->daddr)));
    cout << "Packet Num [" << dec << packet_num++ << "]" << endl;
    cout << "Src MAC: "; cout_mac(ethernet->h_source);
    cout << "Dst MAC: "; cout_mac(ethernet->h_dest);
    cout << "Ether type: "; cout_ethtype(ethernet->h_proto);
    cout << "Src IP: " << saddr << endl;
    cout << "Dst IP: " << daddr << endl;
    cout << "Next Layer Protocol: " << (ip->protocol == 47 ? "GRE" : "???") << endl;
    cout << endl;

    create_gre(saddr, daddr);
};

int main (){
    char errbuf[PCAP_ERRBUF_SIZE];

    // List all devices
    pcap_if_t *devs, *dev;
    if(pcap_findalldevs(&devs, errbuf) == -1){
        cerr << "No device found" << endl;
        exit(1);
    }

    int cnt = 0;
    for(dev = devs; dev != NULL; dev = dev->next){
        cout << ++cnt << " Name: " << dev->name << endl;
    }

    // Get interface number from UI
    string input;
    int num = 0;
    cout << "Insert a number to select interface" << endl;
    getline(cin, input);
    num = stoi(input);
    while(num < 0 || num > cnt){
        cout << "Please input number between 1~" << cnt << endl;
        getline(cin, input);
        num = stoi(input);
    }

    // Start lintening
    dev = devs;
    for(int i=0; i<num-1; i++)
        dev = dev->next;
    cout << "Start listening at $" << dev->name << endl;
    create_brg(dev->name);

    // Make sure not to add Src address from itself
    struct pcap_addr *pt = dev->addresses;
    for(struct pcap_addr *pt = dev->addresses; pt != NULL; pt = pt->next)
        if(pt->addr->sa_family == AF_INET)
            gres[inet_ntoa(((struct sockaddr_in *)pt->addr)->sin_addr)] = "";

    // Packet filtering
    cout << "Insert BPF filter expression: " << endl;
    getline(cin, input);
    cout << "filter: " << input << endl;

    // Capture packet
    pcap_t *handle;
    struct bpf_program *fp;

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        cerr << "Could not open device " << dev->name << ": " << errbuf << endl;
        exit(1);
    }
    if(pcap_compile(handle, fp, input.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0){
        cerr << "pcap_compile error: " << pcap_geterr(handle) << endl;
        exit(1);
    }
    if(pcap_setfilter(handle, fp) < 0){
        cerr << "pcap_setfilter error" << pcap_geterr(handle) << endl;
        exit(1);
    }
    if(pcap_loop(handle, -1, pcap_callback, NULL) < 0){
        cerr << "pcap_loop error" << endl;
        exit(1);
    }
}
