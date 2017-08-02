cmake_minimum_required(VERSION 3.8)
project(WLAN_Crack)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES PacketSender.h PacketSender.cpp PacketSniffer.h PacketSniffer.cpp main.cpp ARPPacketSender.cpp ARPPacketSender.h WLAN-Crack.h)
add_executable(WLAN_Crack ${SOURCE_FILES})

target_link_libraries(WLAN_Crack tins)