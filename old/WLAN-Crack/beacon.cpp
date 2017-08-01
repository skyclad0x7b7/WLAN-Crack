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

#include "beacon.h"

Beacon::Beacon() : channel(1), endFlag(false) {
    apInfoStream.open("apInfo.txt");
}

Beacon::Beacon(char *fileName) : channel(1), endFlag(false) {
    apInfoStream.open(fileName);
}

void Beacon::rotateChannel() {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    char chan[64] = {0};
    for(channel = 1; channel<=13; channel++) {
        sprintf(chan, "iwconfig wlan0 channel %d", channel);
        system(chan);
        std::clog << "[*] Channel Changed : " << channel << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    endFlag = true;
    for(int i = 0; i < apList.size(); ++i) {
        apInfoStream << apList[i].getChannel() << " ) " << apList[i].getSsid() << " - " << apList[i].getMac() << std::endl;
    }
}

void Beacon::saveApInfo() {
    std::clog << "[*] Start Saving AP Info" << std::endl;
    std::thread channelThread(&Beacon::rotateChannel, this);
    std::thread sniffingThread(&Beacon::startSniffing, this);
    channelThread.join();
    sniffingThread.join();
}

void Beacon::startSniffing() {
    Sniffer sniffer("wlan0", Sniffer::promisc_type::NON_PROMISC, "", true);
    sniffer.sniff_loop(make_sniffer_handler(this, &Beacon::packetHandler));
}

bool Beacon::packetHandler(PDU& pdu) {
    if(endFlag) return false;
    try {
        if(pdu.find_pdu<Dot11Beacon>()) {
            if(!isIn(pdu.rfind_pdu<Dot11Beacon>().addr3())) {
                std::string ssid = (pdu.rfind_pdu<Dot11Beacon>().ssid()[0] == '\0') ? std::string("Broadcast") : pdu.rfind_pdu<Dot11Beacon>().ssid();
                apList.push_back(AP(
                        ssid,
                        pdu.rfind_pdu<Dot11Beacon>().addr3(),
                        channel
                ));
                std::clog << "[*] AP Added : " << ssid << std::endl;
            }
        }
    } catch(std::runtime_error& error) {
        std::clog << "[*] Error Occured. Restart." << std::endl;
    }
    return true;
}

bool Beacon::isIn(Dot11::address_type target) {
    for(int i = 0; i < apList.size(); ++i) {
        if(apList[i].getMac() == target) return true;
    }
    return false;
}