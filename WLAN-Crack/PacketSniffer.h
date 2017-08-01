#ifndef WLAN_CRACK_PacketSniffer_H
#define WLAN_CRACK_PacketSniffer_H

#pragma once

#include <iostream>
#include <string>

#include <tins/tins.h>

namespace WLAN_CRACK
{
	class PacketSniffer()
	{
	private:
        Tins::Sniffer m_sniffer;
        Tins::SnifferConfiguration m_snifferConfig;
	public:
        PacketSniffer(const char *interface, const char *filter);
	}
}

#endif