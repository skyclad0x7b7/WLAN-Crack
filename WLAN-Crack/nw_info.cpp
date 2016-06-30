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

#include "nw_info.h"

NW_Info::NW_Info(char *_gateway, char *_victim) {
    try {
        m_gateway = _gateway;
        m_victim = _victim;
        m_iface = m_gateway;
        m_myInfo = m_iface.addresses();
    } catch(std::runtime_error& error) {
        fprintf(stderr, "[*] Please input ip address correctly!!\n");
        exit(1);
    }
    m_pSender.default_interface("wlan0");
    m_gateway_hw = Utils::resolve_hwaddr(m_iface, m_gateway, m_pSender);
    m_victim_hw = Utils::resolve_hwaddr(m_iface, m_victim, m_pSender);
    m_config.set_promisc_mode(false);
}