//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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
// connector_manager.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef CONNECTOR_MANAGER_H
#define CONNECTOR_MANAGER_H

// Factory for Connectors.

#include <string>

#include "framework/connector.h"

namespace snort
{
class Module;
struct SnortConfig;
}

//-------------------------------------------------------------------------

class ConnectorManager
{
public:
    static void add_plugin(const snort::ConnectorApi* api);
    static void dump_plugins();
    static void release_plugins();

    static void instantiate(const snort::ConnectorApi*, snort::Module*, snort::SnortConfig*);
    static snort::Connector::Direction is_instantiated(const std::string& name);
    static void update_thread_connector(const std::string& connector_name, int instance_id, snort::Connector* connector);


    static void thread_init();
    static void thread_reinit();
    static void thread_term();

    /* get_connector() returns the thread-specific object. */
    static snort::Connector* get_connector(const std::string& name);
};

#endif

