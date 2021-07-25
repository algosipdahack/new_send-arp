#ifndef MYHEADER_H
#define MYHEADER_H

#endif // MYHEADER_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#define BROADCAST "FF:FF:FF:FF:FF:FF"
#define NONE "00:00:00:00:00:00"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)
EthArpPacket FindMac(char* target,pcap_t* handle,char* my_ip, char* my_mac);
void arp(char* sender, char* target,pcap_t* handle,char* my_ip, char* my_mac);
int getIPAddress(char *ip_addr,char* dev);
int getMacAddress(char *mac,char* dev);
