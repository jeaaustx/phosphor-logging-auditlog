#include "auditLogMgr.hpp"
#include "auditLogParser.hpp"

#include <auparse.h>
#include <libaudit.h>

#include <phosphor-logging/lg2.hpp>

#include <cstring>
#include <string>

namespace phosphor
{
namespace auditlog
{

/**
 * @brief Closes connection for recording audit events
 */
void ALManager::auditClose(void)
{
    if (auditfd >= 0)
    {
        audit_close(auditfd);
        auditfd = -1;
        lg2::debug("Audit log closed.");
    }

    return;
}

/**
 * @brief Opens connection for recording audit events
 *
 * Reuses prior connection if available.
 *
 * @return If connection was successful or not
 */
bool ALManager::auditOpen(void)
{
    if (auditfd < 0)
    {
        /* Blocking opening of audit connection */
        if (!tryOpen)
        {
            lg2::debug("Audit connection disabled");
            return false;
        }

        auditfd = audit_open();

        if (auditfd < 0)
        {
            lg2::error("Error opening audit socket : {ERRNO}", "ERRNO", errno);
            return false;
        }
        lg2::debug("Audit fd created : {AUDITFD}", "AUDITFD", auditfd);
    }

    return true;
}

/**
 * @brief Establishes new connection for recording audit events
 *
 * Closes any existing connection and tries to create a new connection.
 *
 * @return If new connection was successful or not
 */
bool ALManager::auditReopen(void)
{
    auditClose();
    return auditOpen();
}

/**
 * @brief Sets state for audit connection
 * @param[in] enable    New state for audit connection.
 *			If false, then any existing connection will be closed.
 */
void ALManager::auditSetState(bool enable)
{
    if (enable == false)
    {
        auditClose();
    }

    tryOpen = enable;

    lg2::debug("Audit state: tryOpen = {TRYOPEN}", "TRYOPEN", tryOpen);

    return;
}

/**
 * @brief Appends item to strBuf only if strBuf won't exceed maxBufSize
 *
 * @param[in,out] strBuf Buffer to append up to maxBufSize only
 * @param[in] maxBufSize Maximum length of strBuf
 * @param[in] item String to append if it will fit within maxBufSize
 *
 * @return True if item was appended
 */
bool ALManager::appendItemToBuf(std::string& strBuf, size_t maxBufSize,
                                const std::string& item)
{
    if (strBuf.length() + item.length() > maxBufSize)
    {
        return false;
    }
    strBuf += item;
    return true;
}

} // namespace auditlog
} // namespace phosphor
