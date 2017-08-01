#ifndef WLAN_CRACK_PacketSniffer_H
#define WLAN_CRACK_PacketSniffer_H

#pragma once

#include <iostream>
#include <string>

#include <tins/tins.h>

namespace WLAN_CRACK
{
    /* This class should be inherited and should implement method 'PacketHandler'. */
    class PacketSniffer
    {
    private:
        Tins::Sniffer *m_pSniffer = NULL;
        Tins::SnifferConfiguration m_snifferConfig;
        virtual bool PacketHandler(Tins::PDU&) = 0;
    public:
        PacketSniffer(const char *interface, const char *filter);
        void StartSniffing();
    };
}

#endif