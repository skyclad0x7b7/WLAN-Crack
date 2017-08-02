#include "PacketSender.h"

namespace WLAN_CRACK
{
    // Constructor
    PacketSender::PacketSender(const char *interface)
    {
        m_sender.default_interface(interface);
    }

    // Destructor
    PacketSender::~PacketSender()
    {

    }
}