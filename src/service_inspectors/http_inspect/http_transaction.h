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
// http_transaction.h author Tom Peters <thopeter@cisco.com>

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "http_common.h"
#include "http_enum.h"
#include "http_event.h"
#include "http_flow_data.h"

class HttpMsgRequest;
class HttpMsgStatus;
class HttpMsgHeader;
class HttpMsgTrailer;
class HttpMsgSection;
class HttpMsgBody;
class HttpMsgHeadShared;

class HttpTransaction
{
public:
    ~HttpTransaction();
    static HttpTransaction* attach_my_transaction(HttpFlowData*,
        HttpCommon::SourceId, snort::Flow* const);
    static void delete_transaction(HttpTransaction*, HttpFlowData*);

    HttpMsgRequest* get_request() const { return request; }
    void set_request(HttpMsgRequest* request_) { request = request_; }

    HttpMsgStatus* get_status() const { return status; }
    void set_status(HttpMsgStatus* status_) { status = status_; }

    HttpMsgHeader* get_header(HttpCommon::SourceId source_id) const { return header[source_id]; }
    void set_header(HttpMsgHeader* header_, HttpCommon::SourceId source_id);

    HttpMsgTrailer* get_trailer(HttpCommon::SourceId source_id) const
    { return trailer[source_id]; }
    void set_trailer(HttpMsgTrailer* trailer_, HttpCommon::SourceId source_id)
    { trailer[source_id] = trailer_; }
    void set_body(HttpMsgBody* latest_body);

    HttpInfractions* get_infractions(HttpCommon::SourceId);

    void set_one_hundred_response();
    bool final_response() const { return !second_response_expected; }

    void add_body_len(HttpCommon::SourceId source_id, uint64_t len)
    { body_len[source_id] += len; }
    uint64_t get_body_len(HttpCommon::SourceId source_id) const
    { return body_len[source_id]; }
    uint8_t get_info_code() const;
    const Field& get_info_msg() const;
    void add_filename(HttpCommon::SourceId source_id, const char* fname, uint32_t flen,
        const char* ftype, uint32_t tlen);
    void add_filename(HttpCommon::SourceId source_id,
        const std::string& fname, const std::string& ftype);
    const std::string& get_filename(HttpCommon::SourceId source_id) const
    { return filename[source_id]; }
    const std::string& get_content_type(HttpCommon::SourceId source_id) const
    { return content_type[source_id]; }
  
    void clear_section();
    bool is_clear() const { return active_sections == 0; }
    void garbage_collect();

    HttpTransaction* next = nullptr;

private:
    HttpTransaction(HttpFlowData*, snort::Flow* const);
    void archive_section(HttpMsgSection*, HttpMsgSection**);
    void archive_status(HttpMsgStatus*);
    void archive_header(HttpMsgHeader*);
    void publish_end_of_transaction();
    void append_separator_if_needed(HttpCommon::SourceId);

    HttpFlowData* const session_data;

    uint64_t active_sections = 0;

    HttpMsgRequest* request = nullptr;
    HttpMsgStatus* status = nullptr;
    HttpMsgHeader* header[2] = { nullptr, nullptr };
    HttpMsgTrailer* trailer[2] = { nullptr, nullptr };
    HttpMsgBody* body_list = nullptr;
    HttpMsgSection* archive_status_list = nullptr;
    HttpMsgSection* archive_hdr_list = nullptr;
    HttpInfractions* infractions[2];

    bool response_seen = false;
    bool one_hundred_response = false;
    bool second_response_expected = false;

    // This is a form of reference counting that prevents premature/double deletion of a
    // transaction in the fairly rare case where the request and response are received in
    // parallel.
    bool shared_ownership = false;

    unsigned pub_id;
    snort::Flow* const flow;

    uint64_t body_len[2] = { 0, 0 };
    std::string filename[2];
    std::string content_type[2];

    // Estimates of how much memory http_inspect uses to process a transaction
    static const uint16_t small_things = 400; // minor memory costs not otherwise accounted for
    static const uint16_t transaction_memory_usage_estimate;
};

#endif

