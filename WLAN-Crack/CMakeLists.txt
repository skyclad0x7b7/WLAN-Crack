cmake_minimum_required(VERSION 3.5)
project(WLAN_Crack)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -ltins")

set(SOURCE_FILES main.cpp mitm.cpp mitm.h nw_info.h wlan_crack.h nw_info.cpp dns_spoofer.cpp dns_spoofer.h deauth.cpp deauth.h)

add_executable(WLAN_Crack ${SOURCE_FILES})