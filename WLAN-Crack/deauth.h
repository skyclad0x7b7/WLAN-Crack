//
// Created by root on 6/30/16.
//

#ifndef WLAN_CRACK_DEAUTH_H
#define WLAN_CRACK_DEAUTH_H

#include <iostream>
#include <tins/tins.h>
#include <string>
#include <thread>
#include <chrono>

using namespace Tins;

class Deauth {
protected:
    Dot11::address_type m_victim;
    PacketSender pSender;
    void sendDeauth(Dot11::address_type, Dot11::address_type);
    void startSniffing();
    void startSniffingOne(Dot11::address_type);
    bool packetHandler(PDU&);
    void changeChannel();
public:
    void deauthOne(Dot11::address_type);
    void deauthAll();
};


#endif //WLAN_CRACK_DEAUTH_H
