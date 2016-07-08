//
// Created by root on 6/30/16.
//

#ifndef WLAN_CRACK_DEAUTH_H
#define WLAN_CRACK_DEAUTH_H

#include <iostream>
#include <tins/tins.h>
#include <thread>
#include <chrono>

using namespace Tins;

class Deauth {
protected:
    void startSniffing();
    bool packetHandler(PDU&);
public:
    void sendDeauth(char *input_ap, char *input_st);
    void deauthAll();
};


#endif //WLAN_CRACK_DEAUTH_H
