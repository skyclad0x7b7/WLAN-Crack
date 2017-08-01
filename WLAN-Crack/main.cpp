//
// Created by skyclad on 7/31/17.
//
#include "PacketSniffer.h"

int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "[-] Usage : " << argv[0] << " [interface] [filter]" << std::endl;
        return -1;
    }
    WLAN_CRACK::PacketSniffer(argv[1], argv[2]);
    return 0;
}