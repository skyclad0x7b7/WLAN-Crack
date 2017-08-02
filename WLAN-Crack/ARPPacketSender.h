//
// Created by skyclad on 8/2/17.
//

#ifndef WLAN_CRACK_ARPPACKETSENDER_H
#define WLAN_CRACK_ARPPACKETSENDER_H

#pragma once

#include <thread>
#include <chrono>

#include "WLAN-Crack.h"

namespace WLAN_CRACK {
    class ARPPacketSender : public PacketSender
    {
    private:
        Tins::NetworkInterface m_iface;
        Tins::NetworkInterface::Info m_localInfo;
        Tins::IPv4Address m_ipv4Gateway;
        Tins::EthernetII::address_type m_hwGateway;
    public:
        ARPPacketSender(const char *interface, const char *gateway);
        bool DoARPSpoofing(const char *victim);
    };
}
#endif //WLAN_CRACK_ARPPACKETSENDER_H
