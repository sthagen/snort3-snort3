//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifndef ICMP_SESSION_H
#define ICMP_SESSION_H

#include <sys/time.h>

#include "flow/session.h"

#include "icmp_module.h"

class IcmpSession : public Session
{
public:
    IcmpSession(snort::Flow*);
    ~IcmpSession() override;

    bool setup(snort::Packet*) override;
    int process(snort::Packet*) override;
    void clear() override;
    void count_stale_packet() override
    { icmpStats.stale_packets++; }
public:
    uint32_t echo_count = 0;
    struct timeval ssn_time = {};
};

void icmp_stats();
void icmp_reset();

#endif

