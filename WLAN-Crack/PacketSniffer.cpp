#include "PacketSniffer.h"

namespace WLAN_CRACK
{
    PacketSniffer::PacketSniffer(const char *interface, const char *filter)
    {
        m_snifferConfig.set_filter(filter);
        m_pSniffer = new Tins::Sniffer(interface, m_snifferConfig);
        std::clog << "[*] Sniffer Created with interface (" << interface << "), filter (" << filter << ")" << std::endl;
    }

    void PacketSniffer::StartSniffing()
    {
        if(m_pSniffer == NULL)
            return;
        m_pSniffer->sniff_loop(Tins::make_sniffer_handler(this, &PacketSniffer::PacketHandler));
    }
}