#include "PacketSniffer.h"

namespace WLAN_CRACK
{
    // Constructor
    PacketSniffer::PacketSniffer(const char *interface, const char *filter = nullptr)
    {
        if(filter != nullptr)
            m_snifferConfig.set_filter(filter);
        m_pSniffer = new Tins::Sniffer(interface, m_snifferConfig);
        std::clog << "[*] Sniffer Created with interface (" << interface << "), filter (" << filter << ")" << std::endl;
    }

    // Destructor
    PacketSniffer::~PacketSniffer()
    {
        if(m_pSniffer != nullptr) {
            delete m_pSniffer;
            m_pSniffer = nullptr;
        }
    }

    bool PacketSniffer::SetFilter(const char *filter)
    {
        return m_pSniffer->set_filter(filter);
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