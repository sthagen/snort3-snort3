//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

// expect_cache.h author Russ Combs <rucombs@cisco.com>

#ifndef EXPECT_FLOW_H
#define EXPECT_FLOW_H

// ExpectCache is used to track anticipated flows (like ftp data channels).
// when the flow is found, it updated with the given info.

//-------------------------------------------------------------------------
// data structs
// -- key has IP address and port pairs; one port must be zero (wild card)
//    forming a 3-tuple
// -- node struct is stored in hash table by key
// -- each node struct has one or more list structs linked together
// -- each list struct has a list of flow data
// -- when a new expect is added, a new list struct is created if a new
//    node is created or the last list struct of an existing node already
//    has the same preproc id in the flow data list
// -- when a new expect is added, the last list struct is used if the
//    given preproc id is not already in the flow data list
// -- nodes are preallocated and stored in hash table; if there is no node
//    available when an expect is added, LRU nodes are pruned
// -- list structs are also preallocated and stored in free list; if there
//    is no list struct available when an expect is added, LRU nodes are
//    pruned freeing up both nodes and list structs
// -- the number of list structs per node is capped at MAX_LIST; once
//    reached, requests to add new expects requiring new list structs fail
// -- the number of data structs per list struct is not capped
// -- example:  ftp preproc adds a new 3-tuple twice for 2 expected data
//    channels -> new node with 2 list structs linked to it
// -- example:  ftp preproc adds a new 3-tuple once and then another
//    preproc expects the same 3-tuple -> new node with one list struct
//    is created for ftp and the next request goes in that same list
//    struct
// -- new list structs are appended to node's list struct chain
// -- matching expected sessions are pulled off from the head of the node's
//    list struct chain
//
// FIXIT-M expiration is by node struct but should be by list struct, ie
//    individual sessions, not all sessions to a given 3-tuple
//    (this would make pruning a little harder unless we add linkage
//    a la FlowCache)
//-------------------------------------------------------------------------

#include <memory>
#include <unordered_map>
#include <vector>

#include "flow/flow_data.h"
#include "main/snort_types.h"

struct ExpectNode;

namespace snort
{
struct Packet;

struct SO_PUBLIC ExpectFlow
{
    ExpectFlow* next = nullptr;
    // This cannot use a unique_ptr because we need to move to a real flow during realization
    std::vector<FlowData*> data;

    ExpectFlow() = default;
    ~ExpectFlow();
    void clear();
    void add_flow_data(FlowData*);
    FlowData* get_flow_data(unsigned);
    static std::vector<ExpectFlow*>* get_expect_flows();
    static void reset_expect_flows();
    static void handle_expected_flows(const Packet*);
};
}

#endif

