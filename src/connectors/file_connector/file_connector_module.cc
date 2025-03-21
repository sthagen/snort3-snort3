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

// file_connector_module.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_connector_module.h"

using namespace snort;

static const Parameter file_connector_params[] =
{
    { "connector", Parameter::PT_STRING, nullptr, nullptr,
      "connector name" },

    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "channel name" },

    { "text_format", Parameter::PT_BOOL, nullptr, "false",
      "skip header and add newline at the end of the message" },

    { "direction", Parameter::PT_ENUM, "receive | transmit | duplex", nullptr,
      "usage" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo file_connector_pegs[] =
{
    { CountType::SUM, "messages", "total messages" },
    { CountType::END, nullptr, nullptr }
};

extern THREAD_LOCAL SimpleStats file_connector_stats;
extern THREAD_LOCAL ProfileStats file_connector_perfstats;

//-------------------------------------------------------------------------
// file_connector module
//-------------------------------------------------------------------------

FileConnectorModule::FileConnectorModule() :
    Module(FILE_CONNECTOR_NAME, FILE_CONNECTOR_HELP, file_connector_params, true)
{ }

ProfileStats* FileConnectorModule::get_profile() const
{ return &file_connector_perfstats; }

// clear my working config and hand-over the compiled list to the caller
ConnectorConfig::ConfigSet FileConnectorModule::get_and_clear_config()
{ return std::move(config_set); }

bool FileConnectorModule::begin(const char*, int, SnortConfig*)
{
    if (!config)
        config = std::make_unique<FileConnectorConfig>();

    return true;
}

bool FileConnectorModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("connector") )
        config->connector_name = v.get_string();

    else if ( v.is("name") )
        config->name = v.get_string();

    else if ( v.is("text_format") )
        config->text_format = v.get_bool();

    else if ( v.is("direction") )
    {
        switch ( v.get_uint8() )
        {
        case 0:
            config->direction = Connector::CONN_RECEIVE;
            break;
        case 1:
            config->direction = Connector::CONN_TRANSMIT;
            break;
        case 2:
            config->direction = Connector::CONN_DUPLEX;
            break;
        default:
            return false;
        }
    }
    return true;
}

bool FileConnectorModule::end(const char*, int idx, SnortConfig*)
{
    if (idx != 0)
        config_set.emplace_back(std::move(config));

    return true;
}

const PegInfo* FileConnectorModule::get_pegs() const
{ return file_connector_pegs; }

PegCount* FileConnectorModule::get_counts() const
{ return (PegCount*)&file_connector_stats; }

