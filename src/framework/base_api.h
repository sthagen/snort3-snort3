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
// base_api.h author Russ Combs <rucombs@cisco.com>

#ifndef BASE_API_H
#define BASE_API_H

// BaseApi is the struct at the front of every plugin api and provides the
// data necessary for common management of plugins.  in addition to basic
// usage fields, it provides module instantiation and release functions, as
// well as additional data to help detect mismatched builds etc.

#include <cstdint>

// set options to API_OPTIONS to ensure compatibility
#ifndef API_OPTIONS
#include "framework/api_options.h"
#endif

// the current version of the Snort API
// must be prefixed to subtype version

// depends on includes installed in framework/snort_api.h
// see framework/plugins.h

#define BASE_API_VERSION 22

// set the reserved field to this to be future proof
#define API_RESERVED 0

enum PlugType
{
    PT_CODEC,
    PT_INSPECTOR,
    PT_IPS_ACTION,
    PT_IPS_OPTION,
    PT_SEARCH_ENGINE,
    PT_SO_RULE,
    PT_LOGGER,
    PT_CONNECTOR,
    PT_POLICY_SELECTOR,
    PT_MP_TRANSPORT,
    PT_MAX
};

namespace snort
{
class Module;
typedef Module* (* ModNewFunc)();
typedef void (* ModDelFunc)(Module*);

// if we inherit this we can't use a static initializer list :(
// so BaseApi must be the prefix (ie 1st member) of all plugin api
struct BaseApi
{
    PlugType type;
    uint32_t size;          // sizeof(plugin-api)
    uint32_t api_version;   // (BASE_API_VERSION << 16) | plugin-api-version)
    uint32_t version;       // version of plugin
    uint64_t reserved;      // zero
    const char* options;    // API_OPTIONS
    const char* name;       // plugin name
    const char* help;       // short help text
    ModNewFunc mod_ctor;
    ModDelFunc mod_dtor;
};
}
#endif

