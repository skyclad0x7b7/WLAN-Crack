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

#ifndef WLAN_CRACK_DEAUTH_H
#define WLAN_CRACK_DEAUTH_H

#include <iostream>
#include <tins/tins.h>
#include <string>
#include <thread>
#include <chrono>

using namespace Tins;

class Deauth {
protected:
    Dot11::address_type m_victim;
    PacketSender pSender;
    void sendDeauth(Dot11::address_type, Dot11::address_type);
    void startSniffing();
    void startSniffingOne();
    bool packetHandler(PDU&);
    bool packetHandlerOne(PDU &pdu);
    void rotateChannel();
    void changeChannel(int);
public:
    Deauth();
    void deauthOne(Dot11::address_type, int);
    void deauthAll();
};


#endif //WLAN_CRACK_DEAUTH_H
