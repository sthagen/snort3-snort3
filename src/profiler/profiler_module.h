//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// profiler_module.h author Russ Combs <rucombs@cisco.com>

#ifndef PROFILER_MODULE_H
#define PROFILER_MODULE_H

#include "framework/module.h"

#include "profiler.h"

class ProfilerModule : public snort::Module
{
public:
    ProfilerModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    snort::ProfileStats* get_profile(unsigned, const char*&, const char*&) const override;
    const snort::Command* get_commands() const override;

    Usage get_usage() const override
    { return GLOBAL; }
};

#endif
