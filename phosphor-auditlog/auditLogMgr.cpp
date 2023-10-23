#include "auditLogMgr.hpp"

#include "auditLogParser.hpp"

#include <libaudit.h>

#include <phosphor-logging/lg2.hpp>

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
     * TODO: Incorporate this in the constructor
     */
    if (auditParser.openParsedFile(filePath))
    {
        /* Loop over all the events */
        while (auditParser.auditNextEvent())
        {
            nEvent++;
            lg2::debug("Getting event: {NEVENT}", "NEVENT", nEvent);

            auditParser.parseEvent();
        }
    }

    return;
}

} // namespace auditlog
} // namespace phosphor
