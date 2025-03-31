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

// unixdomain_connector_module.h author Umang Sharma <umasharm@cisco.com>

#ifndef UNIXDOMAIN_CONNECTOR_MODULE_H
#define UNIXDOMAIN_CONNECTOR_MODULE_H

#include "framework/connector.h"
#include "framework/module.h"

#include <memory>

#include "unixdomain_connector_config.h"

#define UNIXDOMAIN_CONNECTOR_NAME "unixdomain_connector"
#define UNIXDOMAIN_CONNECTOR_HELP "implement the unix domain stream connector"

class UnixDomainConnectorModule : public snort::Module {
public:
    UnixDomainConnectorModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    
    snort::ConnectorConfig::ConfigSet get_and_clear_config();

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    std::unique_ptr<UnixDomainConnectorConfig> config;
    snort::ConnectorConfig::ConfigSet config_set;
};

#endif // UNIXDOMAIN_CONNECTOR_MODULE_H
