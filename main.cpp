#include "MyHeader.h"

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
		usage();
		return -1;
	}
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    char* my_ip = (char*)malloc(sizeof(char)*4);
    char* my_mac = (char*)malloc(sizeof(char)*6);
    getIPAddress(my_ip,argv[1]);
    getMacAddress(my_mac,argv[1]);
    int cnt = (argc-2)/2;
    for(int i = 1; i<=cnt; ++i){
        char* sender = argv[2*i];
        char* target = argv[1+2*i];
        arp(sender,target,handle,my_ip,my_mac);
    }
	pcap_close(handle);
}
