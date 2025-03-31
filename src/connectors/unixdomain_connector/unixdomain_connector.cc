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

// unixdomain_connector.cc author Umang Sharma <umasharm@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "unixdomain_connector.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#include <iostream>
#include <fcntl.h>
#include <unordered_map>

#include "log/messages.h"
#include "profiler/profiler_defs.h"

#include "unixdomain_connector_module.h"

using namespace snort;
/* Globals ****************************************************************/

THREAD_LOCAL SimpleStats unixdomain_connector_stats;
THREAD_LOCAL ProfileStats unixdomain_connector_perfstats;

/* Module *****************************************************************/

static bool attempt_connection(int& sfd, const char* path) {
    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1) {
        ErrorMessage("UnixDomainC: socket error: %s \n", strerror(errno));
        return false;
    }

    // Set the socket to non-blocking mode
    int flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        ErrorMessage("UnixDomainC: fcntl(F_GETFL) error: %s \n", strerror(errno));
        close(sfd);
        return false;
    }

    if (fcntl(sfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        ErrorMessage("UnixDomainC: fcntl(F_SETFL) error: %s \n", strerror(errno));
        close(sfd);
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
        if (errno != EINPROGRESS) {
            ErrorMessage("UnixDomainC: connect error: %s \n", strerror(errno));
            close(sfd);
            return false;
        }
    }
    return true;
}

// Function to handle connection retries
static void connection_retry_handler(const UnixDomainConnectorConfig& cfg, size_t idx) {
    ConnectorManager::update_thread_connector(cfg.connector_name, idx, nullptr);

    if ( cfg.setup == UnixDomainConnectorConfig::Setup::CALL and cfg.conn_retries) {

        const auto& paths = cfg.paths;

        if (idx >= paths.size())
            return;
        
        uint32_t retry_count = 0; 
        const char* path = paths[idx].c_str();

        while (retry_count < cfg.max_retries) {
            int sfd;
            if (attempt_connection(sfd, path)) {
                // Connection successful
                UnixDomainConnector* unixdomain_conn = new UnixDomainConnector(cfg, sfd, idx);
                LogMessage("UnixDomainC: Connected to %s", path);
                ConnectorManager::update_thread_connector(cfg.connector_name, idx, unixdomain_conn);
                break;
            }

            std::this_thread::sleep_for(std::chrono::seconds(cfg.retry_interval));
            retry_count++;
        }
    }
}

static void start_retry_thread(const UnixDomainConnectorConfig& cfg, size_t idx) {
    std::thread retry_thread(connection_retry_handler, cfg, idx);
    retry_thread.detach();
}

UnixDomainConnector::UnixDomainConnector(const UnixDomainConnectorConfig& unixdomain_connector_config, int sfd, size_t idx)
    : Connector(unixdomain_connector_config), sock_fd(sfd), run_thread(false), receive_thread(nullptr), 
      receive_ring(new ReceiveRing(50)), instance_id(idx), cfg(unixdomain_connector_config) {
    if (unixdomain_connector_config.async_receive) {
        start_receive_thread();
    }
}

UnixDomainConnector::~UnixDomainConnector() {
    stop_receive_thread();
    delete receive_ring;
    if (fcntl(sock_fd, F_GETFD) == -1) {
        if (errno == EBADF) {
            LogMessage("UnixDomainC: Socket %d already closed \n", sock_fd);        
            return;
        }
    }

    close(sock_fd);
}

enum ReadDataOutcome { SUCCESS = 0, TRUNCATED, ERROR, CLOSED, PARTIAL, AGAIN };

static ReadDataOutcome read_data(int sockfd, uint8_t *data, uint16_t length, ssize_t& read_offset)
{
    ssize_t bytes_read, offset;

    offset = read_offset;
    bytes_read = recv(sockfd, data + offset, length - offset, 0);
    if (bytes_read == 0)
    {
        if ( offset != 0 )
            return TRUNCATED;
        return CLOSED;
    }
    if ( bytes_read == -1 )
    {
        if (errno == EAGAIN || errno == EINTR)
        {
            if (offset > 0)
                return PARTIAL;
            return AGAIN;
        }
        return ERROR;
    }
    read_offset = offset + bytes_read;
    if ((offset + bytes_read) < length)
        return PARTIAL;

    return SUCCESS;
}

static ReadDataOutcome read_message_data(int sockfd, uint16_t length, uint8_t *data)
{
    if ( length > 0 )
    {
        ReadDataOutcome rval;
        do
        {
            ssize_t offset = 0;
            rval = read_data(sockfd, data, length, offset);
        } while (rval == PARTIAL || rval == AGAIN);

        if (rval != SUCCESS)
            return rval;
    }

    return SUCCESS;
}


ConnectorMsg* UnixDomainConnector::read_message()
{
    UnixDomainConnectorMsgHdr hdr;
    ReadDataOutcome outcome;

    outcome = read_message_data(sock_fd, sizeof(hdr), (uint8_t*)&hdr);
    if (outcome != SUCCESS)
    {
        if (outcome == CLOSED)
            LogMessage("UnixDomainC Input Thread: Connection closed\n");
        else
            ErrorMessage("UnixDomainC Input Thread: Unable to receive message header: %d\n", (int)outcome);
        return nullptr;
    }

    if (hdr.version != UNIXDOMAIN_FORMAT_VERSION)
    {
        ErrorMessage("UnixDomainC Input Thread: Received header with invalid version 0x%d\n", (int)hdr.version);
        return nullptr;
    }

    uint8_t* data = new uint8_t[hdr.connector_msg_length];

    if ((outcome = read_message_data(sock_fd, hdr.connector_msg_length, data)) != SUCCESS)
    {
        if (outcome == CLOSED)
            LogMessage("UnixDomainC Input Thread: Connection closed while reading message data \n");
        else
            ErrorMessage("UnixDomainC Input Thread: Unable to receive local message data: %d\n", (int)outcome);
        delete[] data;
        return nullptr;
    }

    return new ConnectorMsg(data, hdr.connector_msg_length, true);
}

void UnixDomainConnector::process_receive() {
    struct pollfd pfds[1];
    int rval;

    pfds[0].events = POLLIN;
    pfds[0].fd = sock_fd;
    rval = poll(pfds, 1, 1000);
    if (rval == -1) {
        if (errno != EINTR) {
            char error_msg[1024] = { '\0' };
            if (strerror_r(errno, error_msg, sizeof(error_msg)) == 0)
                ErrorMessage("UnixDomainC Input Thread: Error polling on socket  %d: %s\n", pfds[0].fd, error_msg);
            else
                ErrorMessage("UnixDomainC Input Thread: Error polling on socket %d: (%d)\n", pfds[0].fd, errno);
        }
        return;
    } 
    else if ((pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) 
    {
        ErrorMessage("UnixDomainC Input Thread: Undesirable return event while polling on socket %d: 0x%x\n",
                pfds[0].fd, pfds[0].revents);

        run_thread.store(false, std::memory_order_relaxed);
        
        if (sock_fd != -1)
        {
            close(sock_fd);
            sock_fd = -1;
        }   

        start_retry_thread(cfg, instance_id);
        return;
    } 
    else if (rval > 0 && pfds[0].revents & POLLIN) {
        ConnectorMsg* connector_msg = read_message();
        if (connector_msg && !receive_ring->put(connector_msg)) {
            ErrorMessage("UnixDomainC: Input Thread: overrun\n");
            delete connector_msg;
        }
    }
}

void UnixDomainConnector::receive_processing_thread() {
    while (run_thread.load(std::memory_order_relaxed)) {
        process_receive();
    }
}

void UnixDomainConnector::start_receive_thread() {
    run_thread.store(true, std::memory_order_relaxed);
    receive_thread = new std::thread(&UnixDomainConnector::receive_processing_thread, this);
}

void UnixDomainConnector::stop_receive_thread() {

    if (receive_thread != nullptr) {
        run_thread.store(false, std::memory_order_relaxed);
        if (receive_thread->joinable()) {
            receive_thread->join();
        }
        delete receive_thread;
        receive_thread = nullptr;
    }
}

bool UnixDomainConnector::internal_transmit_message(const ConnectorMsg& msg) {
    if (!msg.get_data() || msg.get_length() == 0)
        return false;

    if (sock_fd < 0) {
        ErrorMessage("UnixDomainC: transmitting to a closed socket\n");
        return false;
    }

    UnixDomainConnectorMsgHdr unixdomainc_hdr(msg.get_length());

    if ( send( sock_fd, (const char*)&unixdomainc_hdr, sizeof(unixdomainc_hdr), 0 ) != sizeof(unixdomainc_hdr) )
    {
        ErrorMessage("UnixDomainC: failed to transmit header\n");
        return false;
    }

    if (send(sock_fd, msg.get_data(), msg.get_length(), 0) != msg.get_length())
        return false;

    return true;
}

bool UnixDomainConnector::transmit_message(const ConnectorMsg& msg, const ID&) {
    return internal_transmit_message(msg);
}

bool UnixDomainConnector::transmit_message(const ConnectorMsg&& msg, const ID&) {
    return internal_transmit_message(msg);
}

ConnectorMsg UnixDomainConnector::receive_message(bool) {
    if (sock_fd < 0)
        return ConnectorMsg();

    ConnectorMsg* received_msg = receive_ring->get(nullptr);

    if (!received_msg)
        return ConnectorMsg();

    ConnectorMsg ret_msg(std::move(*received_msg));
    delete received_msg;

    return ret_msg;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor() {
    return new UnixDomainConnectorModule;
}

static void mod_dtor(Module* m) {
    delete m;
}

static UnixDomainConnector* unixdomain_connector_tinit_call(const UnixDomainConnectorConfig& cfg, const char* path, size_t idx) {
    int sfd;
    if (!attempt_connection(sfd, path)) {
        if (cfg.conn_retries) {
            // Spawn a new thread to handle connection retries
            start_retry_thread(cfg, idx);

            return nullptr; // Return nullptr as the connection is not yet established
        } else {
            close(sfd);
            return nullptr;
        }
    }
    LogMessage("UnixDomainC: Connected to %s", path);
    UnixDomainConnector* unixdomain_conn = new UnixDomainConnector(cfg, sfd, idx);
    return unixdomain_conn;
}

static UnixDomainConnector* unixdomain_connector_tinit_answer(const UnixDomainConnectorConfig& cfg, const char* path, size_t idx) {
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1) {
        ErrorMessage("UnixDomainC: socket error: %s", strerror(errno));
        return nullptr;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    unlink(path);

    if (bind(sfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
        ErrorMessage("UnixDomainC: bind error: %s \n", strerror(errno));
        close(sfd);
        return nullptr;
    }

    if (listen(sfd, 10) == -1) {
        ErrorMessage("UnixDomainC: listen error: %s \n", strerror(errno));
        close(sfd);
        return nullptr;
    }

    int peer_sfd = accept(sfd, nullptr, nullptr);
    if (peer_sfd == -1) {
        ErrorMessage("UnixDomainC: accept error: %s \n", strerror(errno));
        close(sfd);
        return nullptr;
    }

    LogMessage("UnixDomainC: Accepted connection from %s \n", path);
    return new UnixDomainConnector(cfg, peer_sfd, idx);
} 

static bool is_valid_path(const std::string& path) {
    if (path.empty()) {
        return false;
    }

    for (char c : path) {
        if (!isalnum(c) && c != '_' && c != '.' && c != '/' && c != '-') {
            return false;
        }
    }

    return true;
}

// Create a per-thread object
static Connector* unixdomain_connector_tinit(const ConnectorConfig& config) {
    const UnixDomainConnectorConfig& cfg = static_cast<const UnixDomainConnectorConfig&>(config);
    const auto& paths = cfg.paths;
    auto idx = 0;

    if (get_instance_id() >= paths.size())
        return nullptr;
    
    idx = get_instance_id();
    const char* path = paths[idx].c_str();

    if (!is_valid_path(path)) {
        ErrorMessage("UnixDomainC: Invalid path: %s", path);
        return nullptr;
    }

    UnixDomainConnector* unix_conn;

    if (cfg.setup == UnixDomainConnectorConfig::Setup::CALL)
        unix_conn = unixdomain_connector_tinit_call(cfg, path, idx);
    else if (cfg.setup == UnixDomainConnectorConfig::Setup::ANSWER)
        unix_conn = unixdomain_connector_tinit_answer(cfg, path, idx);
    else
        unix_conn = nullptr;

    return unix_conn;
}

static void unixdomain_connector_tterm(Connector* connector) {
    UnixDomainConnector* unix_conn = (UnixDomainConnector*)connector;
    delete unix_conn;
}

static ConnectorCommon* unixdomain_connector_ctor(Module* m) {
    UnixDomainConnectorModule* mod = (UnixDomainConnectorModule*)m;
    ConnectorCommon* unix_connector_common = new ConnectorCommon(mod->get_and_clear_config());
    return unix_connector_common;
}

static void unixdomain_connector_dtor(ConnectorCommon* c) {
    delete c;
}

const ConnectorApi unixdomain_connector_api = {
    {
        PT_CONNECTOR,
        sizeof(ConnectorApi),
        CONNECTOR_API_VERSION,
        2,
        API_RESERVED,
        API_OPTIONS,
        UNIXDOMAIN_CONNECTOR_NAME,
        UNIXDOMAIN_CONNECTOR_HELP,
        mod_ctor,
        mod_dtor
    },
    0,
    nullptr,
    nullptr,
    unixdomain_connector_tinit,
    unixdomain_connector_tterm,
    unixdomain_connector_ctor,
    unixdomain_connector_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* unixdomain_connector[] =
#endif
{
    &unixdomain_connector_api.base,
    nullptr
};
