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
// csv_logger.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_CSV_LOGGER_H
#define EXTRACTOR_CSV_LOGGER_H

#include "framework/value.h"

#include "extractor_logger.h"

class CsvExtractorLogger : public ExtractorLogger
{
public:
    CsvExtractorLogger(snort::Connector* conn) : ExtractorLogger(conn)
    { }

    virtual bool is_strict() const override
    { return true; }

    void add_header(const std::vector<const char*>& field_names, const snort::Connector::ID&) override;
    void add_field(const char*, const char*) override;
    void add_field(const char*, const char*, size_t) override;
    void add_field(const char*, uint64_t) override;
    void add_field(const char*, struct timeval) override;
    void add_field(const char*, const snort::SfIp&) override;
    void add_field(const char*, bool) override;
    void open_record() override;
    void close_record(const snort::Connector::ID&) override;

private:
    std::string buffer;
};

#endif