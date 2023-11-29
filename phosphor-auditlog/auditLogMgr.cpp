#include "auditLogMgr.hpp"

#include "auditLogParser.hpp"

#include <libaudit.h>

#include <phosphor-logging/lg2.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/event.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>

#include <cstring>
#include <string>

namespace phosphor
{
namespace auditlog
{

void ALManager::parseAuditLog(std::string filePath)
{
    int nEvent = 0;
    ALParser auditParser;

    lg2::debug("Method ParseAuditLog filePath={FILEPATH}", "FILEPATH",
               filePath);

    /* Create output file
     * TODO: Incorporate this in the constructor?
     */
    if (auditParser.createParsedFile(filePath))
    {
        /* Loop over all the events */
        while (auditParser.auditNextEvent())
        {
            nEvent++;
#ifdef AUDITLOG_FULL_DEBUG
            lg2::debug("Getting event: {NEVENT}", "NEVENT", nEvent);
#endif // AUDITLOG_FULL_DEBUG

            auditParser.parseEvent();
        }
    }
    else
    {
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Write();
    }

    return;
}

sdbusplus::message::unix_fd ALManager::getAuditLog()
{
        lg2::debug("Method GetAuditLog: {FILE}", "FILE", parsedFile);

        /* TODO: Create parsedFile as tmpfile, or need to handle
         *       appending new events to the file.
         */
        /* TODO: Error handling */
        parseAuditLog(parsedFile);

    // Confirm parsed file exists
    int fd = -1;
    std::error_code ec;
    if (!std::filesystem::exists(parsedFile, ec))
    {
        lg2::error("File {FILE} doesn't exist.", "FILE", parsedFile);
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        return fd;
    }

    fd = open(parsedFile.c_str(), O_RDONLY | O_NONBLOCK);
    if (fd == -1)
    {
        auto e = errno;
        lg2::error("Failed to open parsedFile ERRNO={ERRNO} PATH={PATH}",
                "ERRNO", e, "PATH", parsedFile);
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
    }

        lg2::debug("getAuditLog(): fd={AUDITFD}", "AUDITFD", fd);

    /* Schedule the fd to be closed by sdbusplus when it sends it back over
     * D-Bus.
     */
    sdeventplus::Event event = sdeventplus::Event::get_default();
    fdCloseEventSource = std::make_unique<sdeventplus::source::Defer>(
        event, std::bind(std::mem_fn(&ALManager::closeFD), this, fd,
        std::placeholders::_1));

    return fd;
}

void ALManager::closeFD(int fd, sdeventplus::source::EventBase& /*source*/)
{
    lg2::debug("Closing parsedFile {FD}", "FD", fd);
    close(fd);
    fdCloseEventSource.reset();
}

} // namespace auditlog
} // namespace phosphor
