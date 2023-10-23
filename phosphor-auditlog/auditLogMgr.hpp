#pragma once

#include <libaudit.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>
#include <xyz/openbmc_project/Logging/AuditLog/server.hpp>

#include <string>

namespace phosphor
{
namespace auditlog
{

using ALIface = sdbusplus::xyz::openbmc_project::Logging::server::AuditLog;
using ALObject = sdbusplus::server::object_t<ALIface>;

/** @class ALManager
 *  @brief Configuration for AuditLog server
 *  @details A concrete implementation of the
 *  xyz.openbmc_project.Logging.AuditLog API, in order to
 *  provide audit log support.
 */
class ALManager : public ALObject
{
  public:
    ALManager() = delete;
    ALManager(const ALManager&) = delete;
    ALManager& operator=(const ALManager&) = delete;
    ALManager(ALManager&&) = delete;
    ALManager& operator=(ALManager&&) = delete;

    ~ALManager()
    {
        lg2::debug("Destructing ALManager");
        auditClose();
    }

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    ALManager(sdbusplus::bus_t& bus, const std::string& path) :
        ALObject(bus, path.c_str())
    {
        lg2::debug("Constructing ALManager Path={PATH}", "PATH", path);
    }

    void auditClose(void);
    bool auditOpen(void);
    bool auditReopen(void);
    void auditSetState(bool enable);
    bool appendItemToBuf(std::string& strBuf, size_t maxBufSize,
                         const std::string& item);

    void parseAuditLog(std::string filePath) override;

    sdbusplus::message::unix_fd getAuditLog() override
    {
        int fd = -1;

        lg2::debug("Method GetAuditLog");

        /* Return the system audit log fd to test interface,
         * but will be altered to return the parsed file eventually.
         */
        if (!auditOpen())
        {
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }

        lg2::debug("auditfd={AUDITFD}", "AUDITFD", auditfd);
        fd = auditfd;

        return fd;
    }

    void logEvent(std::string operation, std::string username,
                  std::string ipAddress, std::string hostname, Result result,
                  std::string detailData) override
    {
        if (!auditOpen())
        {
            lg2::error("Error opening audit socket");
            return;
        }

        lg2::debug("auditfd={AUDITFD}", "AUDITFD", auditfd);

        lg2::debug(
            "Method LogEvent op={OPERATION} user={USER} addr={ADDR} host={HOST} result={RESULT} detail={DETAIL}",
            "OPERATION", operation, "USER", username, "ADDR", ipAddress, "HOST",
            hostname, "RESULT", result, "DETAIL", detailData);
    }

  private:
    bool tryOpen = true;
    int auditfd = -1;
};

} // namespace auditlog
} // namespace phosphor
