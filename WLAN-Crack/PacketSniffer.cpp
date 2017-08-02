#include "PacketSniffer.h"

namespace WLAN_CRACK
{
    PacketSniffer::PacketSniffer(const char *interface, const char *filter)
    {
        m_snifferConfig.set_filter(filter);
        m_pSniffer = new Tins::Sniffer(interface, m_snifferConfig);
        std::clog << "[*] Sniffer Created with interface (" << interface << "), filter (" << filter << ")" << std::endl;
    }

    PacketSniffer::~PacketSniffer()
    {
        if(m_pSniffer != nullptr)
            delete m_pSniffer;
    }

    void PacketSniffer::StartSniffing()
    {
        if(m_pSniffer == nullptr)
            return;
        m_pSniffer->sniff_loop(Tins::make_sniffer_handler(this, &PacketSniffer::PacketHandler));
    }

    void PacketSniffer::StartSniffing(bool (*a_PacketHandler)(Tins::PDU& pdu))
    {
        if(m_pSniffer == nullptr)
            return;
        m_pSniffer->sniff_loop(a_PacketHandler);
    }
}