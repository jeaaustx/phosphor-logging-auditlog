#include "auditLogParser.hpp"

#include "auditLogMgr.hpp"

#include <auparse.h>
#include <libaudit.h>

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <cstring>
#include <filesystem>
#include <map>
#include <string>

namespace phosphor
{
namespace auditlog
{

/**
 * @brief Moves parser to point to next event
 *
 * @return false when no more events exist, or on error
 */
bool ALParser::auditNextEvent()
{
    bool haveEvent = false;
    int rc;

    rc = auparse_next_event(au);
    switch (rc)
    {
        case 1:
            /* Success, pointing to next event */
            haveEvent = true;
            break;
        case 0:
            /* No more events */
            haveEvent = false;
            break;
        case -1:
        default:
            /* Failure */
            lg2::error("Failed to parse next event");
            haveEvent = false;
            break;
    }

    return haveEvent;
}

/* TODO:
 *      - Separate the parsing and the writing of the record to the file?
 */

/**
 * @brief Parses next event and each of its records into JSON format
 * @details Writes the audit log events into the parsedFile.
 * Parsed into format for bmcweb to read the parsedFile.
 */
void ALParser::parseEvent()
{
    unsigned int nRecords = auparse_get_num_records(au);

    // The event itself is a record. It may be the only one.
    ALParser::parseRecord();

    /* Handle any additional records for this event */
    for (unsigned int iter = 1; iter < nRecords; iter++)
    {
        auto rc = auparse_next_record(au);

        switch (rc)
        {
            case 1:
            {
                /* Success finding record, parse it! */
                ALParser::parseRecord();
            }
            break;
            case 0:
                /* No more records, something is confused! */
                lg2::error(
                    "Record count ({NRECS}) and records out of sync ({ITER})",
                    "NRECS", nRecords, "ITER", iter);
                break;
            case -1:
            default:
                /* Error */
                lg2::error("Failed on record number={ITER}", "ITER", iter);
                break;
        }
    }
}

/**
 * @brief Parses general audit entry into JSON format
 * @details Used with audit entries without specific handling. Text of audit
 * log message is written as-is.
 */
void ALParser::fillAuditEntry(nlohmann::json& parsedEntry)
{
    parsedEntry["MessageId"] = "OpenBMC.0.5.AuditLogEntry";

    /* MessageArgs: msg */
    auto recMsg = auparse_get_record_text(au);
    nlohmann::json messageArgs = nlohmann::json::array({recMsg});

    parsedEntry["MessageArgs"] = std::move(messageArgs);
}

inline std::string getValue(std::string fieldText)
{
        if (fieldText.starts_with('\"'))
        {
                auto endQuote = fieldText.find('\"', 1);

                if (endQuote != std::string::npos)
                {
                        return fieldText.substr(1, endQuote - 1);
                }
        }

        return fieldText;
}

/**
 * @brief Parses AUDIT_USYS_CONFIG audit entry into JSON format
 * @details Expected fields from audit log entry are split into MessageArgs
 */
void ALParser::fillUsysEntry(nlohmann::json& parsedEntry)
{
    parsedEntry["MessageId"] = "OpenBMC.0.5.AuditLogUsysConfig";

    nlohmann::json messageArgs = nlohmann::json::array();

    /* Map expected fields to MessageArgs index */
    /* TODO: Error handling, make map track if field is found.
     * Can confirm all expected fields are found at end.
     */
    std::map<std::string, int>::const_iterator mapEntry;
    std::map<std::string, int> msgArgMap({{"type", 0},
                                          {"op", 1},
                                          {"acct", 2},
                                          {"exe", 3},
                                          {"hostname", 4},
                                          {"addr", 5},
                                          {"terminal", 6},
                                          {"res", 7}});

    /* Walk the fields and insert mapped fields into messageArgs */
    int fieldIdx = 0;
    int frc;
    do
    {
        fieldIdx++;

        /* can return nullptr */
        const char* fieldName = auparse_get_field_name(au);
        std::string fieldTxt = auparse_get_field_str(au);

        if ((fieldName == nullptr) || (fieldTxt.empty()))
        {
            lg2::error("Unexpected field:{FIELDIDX}", "FIELDIDX", fieldIdx);
            continue;
        }

        mapEntry = msgArgMap.find(fieldName);

        /* Map the field to the message arg, not all fields are args */
        if (mapEntry != msgArgMap.end())
        {
            /* Remove '"' from fieldTxt */
            messageArgs[mapEntry->second] = getValue(fieldTxt);
#ifdef AUDITLOG_FULL_DEBUG
            lg2::debug(
                "Field {NFIELD} : {FIELDNAME} = {FIELDSTR} argIdx = {ARGIDX}",
                "NFIELD", fieldIdx, "FIELDNAME", fieldName, "FIELDSTR",
                fieldTxt.c_str(), "ARGIDX", mapEntry->second);
#endif // AUDITLOG_FULL_DEBUG
        }
#ifdef AUDITLOG_FULL_DEBUG
        else
        {
            lg2::debug("No map entry for {FIELDNAME}", "FIELDNAME", fieldName);
        }
#endif // AUDITLOG_FULL_DEBUG

    } while ((frc = auparse_next_field(au)) == 1);

    /* TODO: Error handling, make sure all the fields we care about
     * exist. If any are missing switch this entry to generic instead.
     */

    parsedEntry["MessageArgs"] = std::move(messageArgs);
}

/**
 * @brief Parses next record into JSON format
 *
 */
void ALParser::parseRecord()
{
    nlohmann::json parsedEntry;

    /* Fill common fields for any record type */
    auto fullTimestamp = auparse_get_timestamp(au);
    if (fullTimestamp == nullptr)
    {
        // TODO: Handle error
        lg2::error("Failed to parse timestamp");
        return;
    }
    parsedEntry["EventTimestamp"] = fullTimestamp->sec;
    parsedEntry["ID"] = std::format("{}.{}:{}", fullTimestamp->sec,
                                    fullTimestamp->milli,
                                    fullTimestamp->serial);

    /* Fill varied args fields based on record type */
    int recType = auparse_get_type(au);

    switch (recType)
    {
        case AUDIT_USYS_CONFIG:
            fillUsysEntry(parsedEntry);
            break;

        default:
            fillAuditEntry(parsedEntry);
            break;
    }

#ifdef AUDITLOG_FULL_DEBUG
    lg2::debug("parsedEntry = {PARSEDENTRY}", "PARSEDENTRY",
               parsedEntry.dump());
#endif // AUDITLOG_FULL_DEBUG

    /* Dump JSON object to parsedFile */
    /* TODO: Buffer writing to file */
    parsedFile << parsedEntry.dump() << '\n';

    return;
}

bool ALParser::createParsedFile(std::string filePath)
{
    std::error_code ec;

    // Check if file already exists. Error out.
    if (std::filesystem::exists(filePath, ec))
    {
        lg2::error("File {FILE} already exists.", "FILE", filePath);
        return false;
    }

    // Create/Open file using trunc
    parsedFile.open(filePath, std::ios::trunc);
    if (parsedFile.fail())
    {
        lg2::error("Failed to open {FILE}", "FILE", filePath);
        return false;
    }

    // Set permissions on file created to match audit.log, 600
    std::filesystem::perms permission = std::filesystem::perms::owner_read |
                                        std::filesystem::perms::owner_write;
    std::filesystem::permissions(filePath, permission);

    return true;
}

} // namespace auditlog
} // namespace phosphor
