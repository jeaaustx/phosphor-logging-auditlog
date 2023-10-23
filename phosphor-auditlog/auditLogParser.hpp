#pragma once

#include <auparse.h>
#include <libaudit.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>
#include <xyz/openbmc_project/Logging/AuditLog/server.hpp>

#include <fstream>
#include <string>

namespace phosphor
{
namespace auditlog
{

/** @class ALParser
 *  @brief Parsing audit log using auparse library services
 *  @details Provides abstraction to auparse library services
 */
class ALParser
{
  public:
    ALParser(const ALParser&) = delete;
    ALParser& operator=(const ALParser&) = delete;
    ALParser(ALParser&&) = delete;
    ALParser& operator=(ALParser&&) = delete;

    /** @brief Constructor to initialize parsing of audit log files
     */
    ALParser()
    {
        lg2::debug("Constructing ALParser");

        au = auparse_init(AUSOURCE_LOGS, nullptr);
        if (au == nullptr)
        {
            lg2::error("Failed to init auparse");
        }
    }

    ~ALParser()
    {
        lg2::debug("Destructor ALParser");
        auparse_destroy(au);
    }

    bool auditNextEvent();
    void parseEvent();
    void parseRecord();
    bool openParsedFile(std::string filePath);

  private:
    auparse_state_t* au;
    std::ofstream parsedFile;
};

} // namespace auditlog
} // namespace phosphor
