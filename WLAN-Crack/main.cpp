//
// Created by skyclad on 7/31/17.
//
#include "PacketSniffer.h"

bool PacketHandler(Tins::PDU& pdu)
{
    if(pdu.find_pdu<Tins::TCP>()){
        const Tins::IP &ip = pdu.rfind_pdu<Tins::IP>();
        const Tins::TCP &tcp = pdu.rfind_pdu<Tins::TCP>();
        std::clog << " *** [" << ip.src_addr() << ":" << tcp.sport() << "] => [" << ip.dst_addr() << ":" << tcp.dport() << "] ***" << std::endl;
    }
    return true;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "[-] Usage : " << argv[0] << " [interface] [filter]" << std::endl;
        return -1;
    }
    WLAN_CRACK::PacketSniffer sniffer(argv[1], argv[2]);
    sniffer.StartSniffing(&PacketHandler);
    return 0;
}