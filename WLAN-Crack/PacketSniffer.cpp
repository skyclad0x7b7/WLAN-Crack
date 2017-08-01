#include "PacketSniffer.h"

namespace WLAN_CRACK
{
    PacketSniffer::PacketSniffer(const char *interface, const char *filter)
    {
        m_snifferConfig.set_filter(filter);
        m_sniffer = Tins::Sniffer(interface, m_snifferConfig);
        std::clog << "[*] Sniffer Created with interface (" << interface << "), filter (" << filter << ")";
    }
}