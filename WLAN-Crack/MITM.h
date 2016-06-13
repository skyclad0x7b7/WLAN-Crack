//
// Created by root on 6/13/16.
//

#ifndef MITMATTACK_MITM_H
#define MITMATTACK_MITM_H
#include <iostream>
#include <tins/tins.h>
#include <thread>
#include <chrono>

using namespace std;
using namespace Tins;

class MITM {
private:
    SnifferConfiguration config;
    NetworkInterface iface;
    NetworkInterface::Info myInfo;
    IPv4Address gateway, victim;
    EthernetII::address_type gateway_hw, victim_hw;
    PacketSender pSender;

public:
    MITM(char *, char *);
    void startMITM();
    bool packetHandler(PDU&);
    void startARPSpoofing();

};

#endif //MITMATTACK_MITM_H
