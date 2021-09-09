#include "net/pdu/wethhdr.h"
#include "net/pdu/warphdr.h"
#include "net/capture/wpcapdevice.h"
#include "net/wrtm.h"
#include "net/wip.h"
#include "net/wmac.h"
#include "net/wintflist.h"
#include "net/packet/wpacket.h"
#include <stdio.h>
#include <stdlib.h>
#include <vector>
using namespace std;
#pragma pack(push,1)
struct Etharp{
    struct WEthHdr eth;
    struct WArpHdr arp;
};
struct flow{
    WIp sip_;
    WMac smac_;
    WIp tip_;
};
#pragma pack(pop)
Etharp sendpacket(WMac dmac, WMac smac, WMac tmac,WIp tip, WIp sip);
