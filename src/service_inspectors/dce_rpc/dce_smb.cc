//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb.cc author Rashmi Pitre <rrp@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb.h"

#include "detection/detection_engine.h"
#include "file_api/file_service.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"

#include "dce_context_data.h"
#include "dce_smb_commands.h"
#include "dce_smb_module.h"
#include "dce_smb_paf.h"
#include "dce_smb_transaction.h"
#include "dce_smb2.h"
#include "dce_smb2_utils.h"

using namespace snort;

static size_t smb_memcap;
THREAD_LOCAL dce2SmbStats dce2_smb_stats;
THREAD_LOCAL ProfileStats dce2_smb_pstat_main;

//-------------------------------------------------------------------------
// debug stuff
//-------------------------------------------------------------------------

static const char* smb_com_strings[SMB_MAX_NUM_COMS] =
{
    "Create Directory",            // 0x00
    "Delete Directory",            // 0x01
    "Open",                        // 0x02
    "Create",                      // 0x03
    "Close",                       // 0x04
    "Flush",                       // 0x05
    "Delete",                      // 0x06
    "Rename",                      // 0x07
    "Query Information",           // 0x08
    "Set Information",             // 0x09
    "Read",                        // 0x0A
    "Write",                       // 0x0B
    "Lock Byte Range",             // 0x0C
    "Unlock Byte Range",           // 0x0D
    "Create Temporary",            // 0x0E
    "Create New",                  // 0x0F
    "Check Directory",             // 0x10
    "Process Exit",                // 0x11
    "Seek",                        // 0x12
    "Lock And Read",               // 0x13
    "Write And Unlock",            // 0x14
    "Unknown",                     // 0X15
    "Unknown",                     // 0X16
    "Unknown",                     // 0X17
    "Unknown",                     // 0X18
    "Unknown",                     // 0X19
    "Read Raw",                    // 0x1A
    "Read Mpx",                    // 0x1B
    "Read Mpx Secondary",          // 0x1C
    "Write Raw",                   // 0x1D
    "Write Mpx",                   // 0x1E
    "Write Mpx Secondary",         // 0x1F
    "Write Complete",              // 0x20
    "Query Server",                // 0x21
    "Set Information2",            // 0x22
    "Query Information2",          // 0x23
    "Locking AndX",                // 0x24
    "Transaction",                 // 0x25
    "Transaction Secondary",       // 0x26
    "Ioctl",                       // 0x27
    "Ioctl Secondary",             // 0x28
    "Copy",                        // 0x29
    "Move",                        // 0x2A
    "Echo",                        // 0x2B
    "Write And Close",             // 0x2C
    "Open AndX",                   // 0x2D
    "Read AndX",                   // 0x2E
    "Write AndX",                  // 0x2F
    "New File Size",               // 0x30
    "Close And Tree Disc",         // 0x31
    "Transaction2",                // 0x32
    "Transaction2 Secondary",      // 0x33
    "Find Close2",                 // 0x34
    "Find Notify Close",           // 0x35
    "Unknown",                     // 0X36
    "Unknown",                     // 0X37
    "Unknown",                     // 0X38
    "Unknown",                     // 0X39
    "Unknown",                     // 0X3A
    "Unknown",                     // 0X3B
    "Unknown",                     // 0X3C
    "Unknown",                     // 0X3D
    "Unknown",                     // 0X3E
    "Unknown",                     // 0X3F
    "Unknown",                     // 0X40
    "Unknown",                     // 0X41
    "Unknown",                     // 0X42
    "Unknown",                     // 0X43
    "Unknown",                     // 0X44
    "Unknown",                     // 0X45
    "Unknown",                     // 0X46
    "Unknown",                     // 0X47
    "Unknown",                     // 0X48
    "Unknown",                     // 0X49
    "Unknown",                     // 0X4A
    "Unknown",                     // 0X4B
    "Unknown",                     // 0X4C
    "Unknown",                     // 0X4D
    "Unknown",                     // 0X4E
    "Unknown",                     // 0X4F
    "Unknown",                     // 0X50
    "Unknown",                     // 0X51
    "Unknown",                     // 0X52
    "Unknown",                     // 0X53
    "Unknown",                     // 0X54
    "Unknown",                     // 0X55
    "Unknown",                     // 0X56
    "Unknown",                     // 0X57
    "Unknown",                     // 0X58
    "Unknown",                     // 0X59
    "Unknown",                     // 0X5A
    "Unknown",                     // 0X5B
    "Unknown",                     // 0X5C
    "Unknown",                     // 0X5D
    "Unknown",                     // 0X5E
    "Unknown",                     // 0X5F
    "Unknown",                     // 0X60
    "Unknown",                     // 0X61
    "Unknown",                     // 0X62
    "Unknown",                     // 0X63
    "Unknown",                     // 0X64
    "Unknown",                     // 0X65
    "Unknown",                     // 0X66
    "Unknown",                     // 0X67
    "Unknown",                     // 0X68
    "Unknown",                     // 0X69
    "Unknown",                     // 0X6A
    "Unknown",                     // 0X6B
    "Unknown",                     // 0X6C
    "Unknown",                     // 0X6D
    "Unknown",                     // 0X6E
    "Unknown",                     // 0X6F
    "Tree Connect",                // 0x70
    "Tree Disconnect",             // 0x71
    "Negotiate",                   // 0x72
    "Session Setup AndX",          // 0x73
    "Logoff AndX",                 // 0x74
    "Tree Connect AndX",           // 0x75
    "Unknown",                     // 0X76
    "Unknown",                     // 0X77
    "Unknown",                     // 0X78
    "Unknown",                     // 0X79
    "Unknown",                     // 0X7A
    "Unknown",                     // 0X7B
    "Unknown",                     // 0X7C
    "Unknown",                     // 0X7D
    "Security Package AndX",       // 0x7E
    "Unknown",                     // 0X7F
    "Query Information Disk",      // 0x80
    "Search",                      // 0x81
    "Find",                        // 0x82
    "Find Unique",                 // 0x83
    "Find Close",                  // 0x84
    "Unknown",                     // 0X85
    "Unknown",                     // 0X86
    "Unknown",                     // 0X87
    "Unknown",                     // 0X88
    "Unknown",                     // 0X89
    "Unknown",                     // 0X8A
    "Unknown",                     // 0X8B
    "Unknown",                     // 0X8C
    "Unknown",                     // 0X8D
    "Unknown",                     // 0X8E
    "Unknown",                     // 0X8F
    "Unknown",                     // 0X90
    "Unknown",                     // 0X91
    "Unknown",                     // 0X92
    "Unknown",                     // 0X93
    "Unknown",                     // 0X94
    "Unknown",                     // 0X95
    "Unknown",                     // 0X96
    "Unknown",                     // 0X97
    "Unknown",                     // 0X98
    "Unknown",                     // 0X99
    "Unknown",                     // 0X9A
    "Unknown",                     // 0X9B
    "Unknown",                     // 0X9C
    "Unknown",                     // 0X9D
    "Unknown",                     // 0X9E
    "Unknown",                     // 0X9F
    "Nt Transact",                 // 0xA0
    "Nt Transact Secondary",       // 0xA1
    "Nt Create AndX",              // 0xA2
    "Unknown",                     // 0XA3
    "Nt Cancel",                   // 0xA4
    "Nt Rename",                   // 0xA5
    "Unknown",                     // 0XA6
    "Unknown",                     // 0XA7
    "Unknown",                     // 0XA8
    "Unknown",                     // 0XA9
    "Unknown",                     // 0XAA
    "Unknown",                     // 0XAB
    "Unknown",                     // 0XAC
    "Unknown",                     // 0XAD
    "Unknown",                     // 0XAE
    "Unknown",                     // 0XAF
    "Unknown",                     // 0XB0
    "Unknown",                     // 0XB1
    "Unknown",                     // 0XB2
    "Unknown",                     // 0XB3
    "Unknown",                     // 0XB4
    "Unknown",                     // 0XB5
    "Unknown",                     // 0XB6
    "Unknown",                     // 0XB7
    "Unknown",                     // 0XB8
    "Unknown",                     // 0XB9
    "Unknown",                     // 0XBA
    "Unknown",                     // 0XBB
    "Unknown",                     // 0XBC
    "Unknown",                     // 0XBD
    "Unknown",                     // 0XBE
    "Unknown",                     // 0XBF
    "Open Print File",             // 0xC0
    "Write Print File",            // 0xC1
    "Close Print File",            // 0xC2
    "Get Print Queue",             // 0xC3
    "Unknown",                     // 0XC4
    "Unknown",                     // 0XC5
    "Unknown",                     // 0XC6
    "Unknown",                     // 0XC7
    "Unknown",                     // 0XC8
    "Unknown",                     // 0XC9
    "Unknown",                     // 0XCA
    "Unknown",                     // 0XCB
    "Unknown",                     // 0XCC
    "Unknown",                     // 0XCD
    "Unknown",                     // 0XCE
    "Unknown",                     // 0XCF
    "Unknown",                     // 0XD0
    "Unknown",                     // 0XD1
    "Unknown",                     // 0XD2
    "Unknown",                     // 0XD3
    "Unknown",                     // 0XD4
    "Unknown",                     // 0XD5
    "Unknown",                     // 0XD6
    "Unknown",                     // 0XD7
    "Read Bulk",                   // 0xD8
    "Write Bulk",                  // 0xD9
    "Write Bulk Data",             // 0xDA
    "Unknown",                     // 0XDB
    "Unknown",                     // 0XDC
    "Unknown",                     // 0XDD
    "Unknown",                     // 0XDE
    "Unknown",                     // 0XDF
    "Unknown",                     // 0XE0
    "Unknown",                     // 0XE1
    "Unknown",                     // 0XE2
    "Unknown",                     // 0XE3
    "Unknown",                     // 0XE4
    "Unknown",                     // 0XE5
    "Unknown",                     // 0XE6
    "Unknown",                     // 0XE7
    "Unknown",                     // 0XE8
    "Unknown",                     // 0XE9
    "Unknown",                     // 0XEA
    "Unknown",                     // 0XEB
    "Unknown",                     // 0XEC
    "Unknown",                     // 0XED
    "Unknown",                     // 0XEE
    "Unknown",                     // 0XEF
    "Unknown",                     // 0XF0
    "Unknown",                     // 0XF1
    "Unknown",                     // 0XF2
    "Unknown",                     // 0XF3
    "Unknown",                     // 0XF4
    "Unknown",                     // 0XF5
    "Unknown",                     // 0XF6
    "Unknown",                     // 0XF7
    "Unknown",                     // 0XF8
    "Unknown",                     // 0XF9
    "Unknown",                     // 0XFA
    "Unknown",                     // 0XFB
    "Unknown",                     // 0XFC
    "Unknown",                     // 0XFD
    "Invalid",                     // 0xFE
    "No AndX Command"              // 0xFF
};

const char* get_smb_com_string(uint8_t b)
{ return smb_com_strings[b]; }

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Dce2SmbInspector : public Inspector
{
public:
    explicit Dce2SmbInspector(const dce2SmbProtoConf&);
    ~Dce2SmbInspector() override;

    void show(const SnortConfig*) const override;
    void eval(Packet*) override;
    void clear(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new Dce2SmbSplitter(c2s); }

    bool can_carve_files() const override
    { return true; }

private:
    dce2SmbProtoConf config;
};

Dce2SmbInspector::Dce2SmbInspector(const dce2SmbProtoConf& pc) : config(pc)
{
}

Dce2SmbInspector::~Dce2SmbInspector()
{
    if (config.smb_invalid_shares)
    {
        DCE2_ListDestroy(config.smb_invalid_shares);
    }
}

void Dce2SmbInspector::show(const SnortConfig*) const
{
    print_dce2_smb_conf(config);
}

void Dce2SmbInspector::eval(Packet* p)
{
    Profile profile(dce2_smb_pstat_main); // cppcheck-suppress unreadVariable

    DCE2_SmbSsnData* dce2_smb_sess = nullptr;
    DCE2_Smb2SsnData* dce2_smb2_sess = nullptr;
    DCE2_SmbVersion smb_version = DCE2_SMB_VERSION_NULL;

    if (p == nullptr)
        return;

    assert(p->has_tcp_data());
    assert(p->flow);

    reset_using_rpkt();

    Dce2SmbFlowData* smb_flowdata = (Dce2SmbFlowData*)p->flow->get_flow_data(Dce2SmbFlowData::inspector_id);
    if (smb_flowdata and smb_flowdata->dce2_smb_session_data)
    {
        smb_version = smb_flowdata->smb_version;
        if (DCE2_SMB_VERSION_1 == smb_version)
            dce2_smb_sess = (DCE2_SmbSsnData*)smb_flowdata->dce2_smb_session_data;
        else
            dce2_smb2_sess = (DCE2_Smb2SsnData*)smb_flowdata->dce2_smb_session_data;
    }
    else
    {
        smb_version = DCE2_Smb2Version(p);

        if (DCE2_SMB_VERSION_1 == smb_version)
        {
            //1st packet of flow in smb1 session, create smb1 session and flowdata
            dce2_smb_sess = dce2_create_new_smb_session(p, &config);
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL
                , p, "smb1 session created\n");
        }
        else if (DCE2_SMB_VERSION_2 == smb_version)
        {
            //1st packet of flow in smb2 session, create smb2 session and flowdata
            dce2_smb2_sess = dce2_create_new_smb2_session(p, &config);
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL
                , p, "smb2 session created\n");
        }
        else
        {
            //smb_version is DCE2_SMB_VERSION_NULL
            //This means there is no flow data and this is not an SMB packet
            //if it is a TCP packet for smb data, the flow must have been
            //already identified with version.
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL
                , p, "non-smb packet detected\n");
            return;
        }
    }

    //  By this time we must know the smb version, have correct smb session data and created
    // flowdata
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
    dce2_detected = 0;
    p->endianness = new DceEndianness();

    if (DCE2_SMB_VERSION_1 == smb_version)
    {
        DCE2_Smb1Process(dce2_smb_sess);
        if (!dce2_detected)
            DCE2_Detect(&dce2_smb_sess->sd);
    }
    else
    {
        DCE2_Smb2Process(dce2_smb2_sess);
        if (!dce2_detected)
            DCE2_Detect(&dce2_smb2_sess->sd);
    }

    delete(p->endianness);
    p->endianness = nullptr;
}

void Dce2SmbInspector::clear(Packet* p)
{
    DCE2_SsnData* sd = get_dce2_session_data(p->flow);
    if ( sd )
        DCE2_ResetRopts(sd, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Dce2SmbModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void dce2_smb_init()
{
    Dce2SmbFlowData::init();
    DCE2_SmbInitGlobals();
    DCE2_SmbInitDeletePdu();
    DceContextData::init(DCE2_TRANS_TYPE__SMB);
}

static void dce2_smb_tinit()
{
    delete smb2_session_cache;
    DCE2_SmbSessionCacheInit(smb_memcap);
}

static void dce2_smb_tterm()
{
    delete smb2_session_cache;
    smb2_session_cache = nullptr;
}

static Inspector* dce2_smb_ctor(Module* m)
{
    Dce2SmbModule* mod = (Dce2SmbModule*)m;
    dce2SmbProtoConf config;
    mod->get_data(config);
    smb_memcap = DCE2_ScSmbMemcap(&config);
    return new Dce2SmbInspector(config);
}

static void dce2_smb_dtor(Inspector* p)
{
    delete p;
}

static const char* dce2_bufs[] =
{
    "dce_iface",
    "dce_stub_data",
    "file_data",
    nullptr
};

const InspectApi dce2_smb_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DCE2_SMB_NAME,
        DCE2_SMB_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    dce2_bufs,
    "netbios-ssn",
    dce2_smb_init,
    nullptr, // pterm
    dce2_smb_tinit, // tinit
    dce2_smb_tterm, // tterm
    dce2_smb_ctor,
    dce2_smb_dtor,
    nullptr, // ssn
    nullptr  // reset
};

