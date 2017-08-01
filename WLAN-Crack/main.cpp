//
// Created by skyclad on 7/31/17.
//
#include "PacketSniffer.h"

class MySniffer : public WLAN_CRACK::PacketSniffer
{
private:
    virtual bool PacketHandler(Tins::PDU& pdu)
    {
        while(true)
        {
            if(pdu.find_pdu<Tins::TCP>()){
                const Tins::IP &ip = pdu.rfind_pdu<Tins::IP>();
                const Tins::TCP &tcp = pdu.rfind_pdu<Tins::TCP>();
                std::clog << " *** [" << ip.src_addr() << ":" << tcp.sport() << "] => [" << ip.dst_addr() << ":" << tcp.dport() << "] ***" << std::endl;
            }
            return true;
        }
        return false;
    }

public:
    MySniffer(const char *interface, const char*filter):PacketSniffer(interface, filter){};
};

int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "[-] Usage : " << argv[0] << " [interface] [filter]" << std::endl;
        return -1;
    }
    MySniffer sniffer(argv[1], argv[2]);
    sniffer.StartSniffing();
    return 0;
}