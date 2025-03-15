//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// service_irc.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_irc.h"

#define IRC_COUNT_THRESHOLD 10

static const char* const IRC_USER="USER ";
static const char* const IRC_NOTICE="NOTICE ";
static const char* const IRC_ERROR="ERROR ";
static const char* const IRC_PONG="PONG ";
static const char* const IRC_PING="PING ";

enum IRCState
{
    IRC_STATE_BEGIN,
    IRC_STATE_MID_PREFIX,
    IRC_STATE_COMMAND_BEGIN,
    IRC_STATE_MID_COMMAND,
    IRC_STATE_MID_NUMERIC_COMMAND,
    IRC_STATE_LINE,
    IRC_STATE_MID_TERM,
    IRC_STATE_FOUND_USER,
    IRC_STATE_USER_USERNAME,
    IRC_STATE_USER_HOSTNAME,
    IRC_STATE_USER_SERVERNAME,
    IRC_STATE_USER_REALNAME_BEGIN,
    IRC_STATE_USER_REALNAME,
    IRC_STATE_USER_MID_TERM
};

class ServiceIRCData : public AppIdFlowData
{
public:
    ~ServiceIRCData() override = default;

    const char* command = nullptr;
    const char* initiator_command = nullptr;
    IRCState state = IRC_STATE_BEGIN;
    unsigned pos = 0;
    IRCState initiator_state = IRC_STATE_BEGIN;
    unsigned initiator_pos = 0;
    unsigned count = 0;
};

IrcServiceDetector::IrcServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "irc";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_IRCD, 0 }
    };

    service_ports =
    {
        { 6667, IpProtocol::TCP, false }
    };

    handler->register_detector(name, this, proto);
}


int IrcServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    if (!args.size)
    {
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;
    }

    ServiceIRCData* id = (ServiceIRCData*)data_get(args.asd);
    if (!id)
    {
        id = new ServiceIRCData;
        data_add(args.asd, id);
    }

    IRCState* state;
    unsigned* pos;
    const char** command;
    const uint8_t* data = args.data;
    const uint8_t* end = (const uint8_t*)(data + args.size);

    if (args.dir == APP_ID_FROM_RESPONDER)
    {
        state = &id->state;
        pos = &id->pos;
        command = &id->command;
    }
    else
    {
        state = &id->initiator_state;
        pos = &id->initiator_pos;
        command = &id->initiator_command;
    }

    for (; data<end; data++)
    {
        switch (*state)
        {
        case IRC_STATE_BEGIN:
            if (*data == ':')
            {
                *state = IRC_STATE_MID_PREFIX;
                break;
            }
        /* Fall through */
        case IRC_STATE_COMMAND_BEGIN:
            if (*data == ' ')
                break;
            else if (isdigit(*data))
            {
                *state = IRC_STATE_MID_NUMERIC_COMMAND;
                *pos = 1;
                break;
            }
            else
            {
                if (args.dir == APP_ID_FROM_RESPONDER)
                {
                    if (*data == IRC_NOTICE[0])
                        *command = IRC_NOTICE;
                    else if (*data == IRC_ERROR[0])
                        *command = IRC_ERROR;
                    else if (*data == IRC_PONG[0])
                        *command = IRC_PONG;
                    else
                        goto fail;
                }
                else
                {
                    if (*data == IRC_USER[0])
                        *command = IRC_USER;
                    else
                    {
                        *state = IRC_STATE_LINE;
                        break;
                    }
                }
            }

            *pos = 1;
            *state = IRC_STATE_MID_COMMAND;
            break;
        case IRC_STATE_MID_COMMAND:
            if (*data != (*command)[*pos])
            {
                if (*command == IRC_PONG && *pos == 1 && *data == IRC_PING[1])
                {
                    *command = IRC_PING;
                }
                else
                    goto fail;
            }
            (*pos)++;
            if (!(*command)[*pos])
            {
                if (args.dir == APP_ID_FROM_RESPONDER)
                {
                    *state = IRC_STATE_LINE;
                }
                else
                {
                    *state = IRC_STATE_USER_USERNAME;
                }
            }
            break;
        case IRC_STATE_LINE:
            if (*data == 0x0D)
                *state = IRC_STATE_MID_TERM;
            else if (*data == 0x0A)
            {
                *state = IRC_STATE_BEGIN;
                if (args.dir == APP_ID_FROM_RESPONDER)
                {
                    id->count++;
                    if (id->count >= IRC_COUNT_THRESHOLD && id->initiator_state ==
                        IRC_STATE_FOUND_USER)
                        goto success;
                }
            }
            break;
        case IRC_STATE_MID_TERM:
            if (*data != 0x0A)
                goto fail;
            *state = IRC_STATE_BEGIN;
            if (args.dir == APP_ID_FROM_RESPONDER)
            {
                id->count++;
                if (id->count >= IRC_COUNT_THRESHOLD && id->initiator_state ==
                    IRC_STATE_FOUND_USER)
                    goto success;
            }
            break;
        case IRC_STATE_MID_NUMERIC_COMMAND:
            if (*pos < 3)
            {
                if (!isdigit(*data))
                    goto fail;
                (*pos)++;
            }
            else
            {
                if (*data != ' ')
                    goto fail;
                *state = IRC_STATE_LINE;
            }
            break;
        case IRC_STATE_MID_PREFIX:
            if (*data == ' ')
                *state = IRC_STATE_COMMAND_BEGIN;
            else if (!isprint(*data))
                goto fail;
            break;
        case IRC_STATE_USER_USERNAME:
            if (*data == ' ')
                *state = IRC_STATE_USER_HOSTNAME;
            else if (*data == 0x0D || *data == 0x0A)
                goto fail;
            break;
        case IRC_STATE_USER_HOSTNAME:
            if (*data == ' ')
                *state = IRC_STATE_USER_SERVERNAME;
            else if (*data == 0x0D || *data == 0x0A)
                goto fail;
            break;
        case IRC_STATE_USER_SERVERNAME:
            if (*data == ' ')
                *state = IRC_STATE_USER_REALNAME_BEGIN;
            else if (*data == 0x0D || *data == 0x0A)
                goto fail;
            break;
        case IRC_STATE_USER_REALNAME_BEGIN:
            if (*data == ':')
                *state = IRC_STATE_USER_REALNAME;
            else
                goto fail;
            break;
        case IRC_STATE_USER_REALNAME:
            if (*data == 0x0D)
                *state = IRC_STATE_USER_MID_TERM;
            else if (*data == 0x0A)
                *state = IRC_STATE_FOUND_USER;
            break;
        case IRC_STATE_USER_MID_TERM:
            if (*data != 0x0A)
                goto fail;
            *state = IRC_STATE_FOUND_USER;
            break;
        case IRC_STATE_FOUND_USER:
            goto inprocess;
        default:
            goto fail;
        }
    }
inprocess:
    service_inprocess(args.asd, args.pkt, args.dir);
    return APPID_INPROCESS;

success:
    return add_service(args.change_bits, args.asd, args.pkt, args.dir, APP_ID_IRCD);

fail:
    if (args.dir == APP_ID_FROM_RESPONDER)
    {
        fail_service(args.asd, args.pkt, args.dir);
    }
    else
    {
        incompatible_data(args.asd, args.pkt, args.dir);
    }
    return APPID_NOMATCH;
}

