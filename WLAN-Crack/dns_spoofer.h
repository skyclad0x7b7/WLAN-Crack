//
// Created by root on 6/30/16.
//

#ifndef WLAN_CRACK_DNS_SPOOFER_H
#define WLAN_CRACK_DNS_SPOOFER_H
#include "nw_info.h"

class DNS_Spoofer : NW_Info {
protected:
    IPv4Address m_server;
public:
    DNS_Spoofer(char *, char *, char *);
    void startSniffing();
    bool packetHandler(PDU&);
};


#endif //WLAN_CRACK_DNS_SPOOFER_H
