//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// json_logger.h author Cisco

#ifndef EXTRACTOR_JSON_LOGGER_H
#define EXTRACTOR_JSON_LOGGER_H

#include <sstream>

#include "framework/value.h"
#include "helpers/json_stream.h"

#include "extractor_logger.h"

class JsonExtractorLogger : public ExtractorLogger
{
public:
    JsonExtractorLogger(snort::Connector* conn) : ExtractorLogger(conn), oss(), js(oss)
    { }

    void add_field(const char*, const char*) override;
    void add_field(const char*, const char*, size_t) override;
    void add_field(const char*, uint64_t) override;
    void add_field(const char*, struct timeval) override;
    void add_field(const char*, const snort::SfIp&) override;
    void add_field(const char*, bool) override;
    void open_record() override;
    void close_record(const snort::Connector::ID&) override;

private:
    std::ostringstream oss;
    snort::JsonStream js;

};

#endif