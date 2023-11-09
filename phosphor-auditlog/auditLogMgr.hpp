#pragma once

#include <libaudit.h>

#include <boost/asio/ip/host_name.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/event.hpp>
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
        hostName = boost::asio::ip::host_name();
    }

    void auditClose(void);
    bool auditOpen(void);
    bool auditReopen(void);
    void auditSetState(bool enable);
    bool appendItemToBuf(std::string& strBuf, size_t maxBufSize,
                         const std::string& item);

    void parseAuditLog(std::string filePath) override;
    sdbusplus::message::unix_fd getAuditLog() override;

    void logEvent(std::string operation, std::string username,
                  std::string ipAddress, Result result,
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
            hostName, "RESULT", result, "DETAIL", detailData);
    }

  private:
    bool tryOpen = true;
    int auditfd = -1;   // Socket connection to audit service
    std::string hostName;
    std::string parsedFile = "/tmp/auditLog.json";

    /**
     * @brief The event source for closing the parsedFile descriptor after it
     *        has been returned from the getEntry D-Bus method.
     */
    std::unique_ptr<sdeventplus::source::Defer> fdCloseEventSource;

    /**
     * @brief Closes the file descriptor passed in.
     * @details This is called from the event loop to close FDs returned from
     * getAuditLog().
     * @param[in] fd - The file descriptor to close
     * @param[in] source - The event source object used
     */
    void closeFD(int fd, sdeventplus::source::EventBase& source);

};

} // namespace auditlog
} // namespace phosphor
