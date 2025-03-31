// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// unixdomain_connector_config.h author Umang Sharma <umasharm@cisco.com>

#ifndef UNIXDOMAIN_CONNECTOR_CONFIG_H
#define UNIXDOMAIN_CONNECTOR_CONFIG_H

#include <string>
#include <vector>

#include "framework/connector.h"
#include "managers/plugin_manager.h"

class UnixDomainConnectorConfig : public snort::ConnectorConfig
{
public:
    enum Setup { CALL, ANSWER };

    UnixDomainConnectorConfig()
    { direction = snort::Connector::CONN_DUPLEX; async_receive = true; }

    std::vector<std::string> paths; 
    Setup setup = {};
    bool conn_retries = false;
    uint32_t retry_interval = 4;
    uint32_t max_retries = 5;
    bool async_receive;
};

#endif

