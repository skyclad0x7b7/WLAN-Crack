#ifndef WLAN_CRACK_PacketSniffer_H
#define WLAN_CRACK_PacketSniffer_H

#pragma once

#include <iostream>
#include <string>

#include <tins/tins.h>

namespace WLAN_CRACK
{
    class PacketSniffer
    {
    private:
        Tins::Sniffer *m_pSniffer = nullptr;
        Tins::SnifferConfiguration m_snifferConfig;
        virtual bool PacketHandler(Tins::PDU&){ return true; };
    public:
        PacketSniffer(const char *interface, const char *filter = nullptr);
        ~PacketSniffer();
        bool SetFilter(const char *filter);

        void StartSniffing();
        void StartSniffing(bool (*a_PacketHandler)(Tins::PDU&));
    };
}

#endif