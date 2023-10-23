#include "auditLogParser.hpp"

#include "auditLogMgr.hpp"

#include <auparse.h>
#include <libaudit.h>

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <cstring>
#include <filesystem>
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

void ALParser::parseEvent()
{
    unsigned int nRecords = auparse_get_num_records(au);

    /* The event itself is a record, and may be the only
     * one
     */
    ALParser::parseRecord();

    /* Handle any additional records for this event */
    for (unsigned int iter = 1; iter < nRecords; iter++)
    {
        auto rc = auparse_next_record(au);
        lg2::debug("Record={ITER} rc={RC}", "ITER", iter, "RC", rc);

        switch (rc)
        {
            case 1:
            {
                /* Success finding record, dump its text */
                ALParser::parseRecord();
            }
            break;
            case 0:
                /* No more records, something is confused! */
                lg2::error("Record count and records out of sync");
                break;
            case -1:
            default:
                /* Error */
                lg2::error("Failed on record number={ITER}", "ITER", iter);
                break;
        }
    }
}

void ALParser::parseRecord()
{
    nlohmann::json parsedEntry;

    /* Parse record into JSon object.
     * All record types will have:
     *   ID
     *   EventTimestamp
     *   MessageArgs[]
     *
     *   MessageArgs vary based on the record type.
     *   For non AUDIT_USYS_CONFIG, the type and message are the only args.
     *   For AUDIT_USYS_CONFIG:
     *          type
     *          op
     *          acct
     *          exe
     *          hostname
     *          addr
     *          terminal
     *          res
     */
    int recType = auparse_get_type(au);

    auto recTypeName = auparse_get_type_name(au);
    parsedEntry["TYPE"] = recTypeName;
    lg2::debug("parsedEntry = {PARSEDENTRY}", "PARSEDENTRY",
               parsedEntry.dump());

    if (recType == AUDIT_USYS_CONFIG)
    {
        lg2::debug("Found one of our events");

        unsigned long serial = auparse_get_serial(au);
        time_t eventTime = auparse_get_time(au);
#if 0
                /* This gives milliseconds, seconds, serial in one, can use to
                 * build unique event ID as well as timestamp
                 */
                 typedef struct
{
        time_t sec;             // Event seconds
        unsigned int milli;     // millisecond of the timestamp
        unsigned long serial;   // Serial number of the event
        const char *host;       // Machine's node name
} au_event_t;
                 /* returns NULL on error */
                 const au_event_t *auparse_get_timestamp(auparse_state_t *au);
#endif

        /* Walk the fields, this is per record */
        unsigned int nFields = auparse_get_num_fields(au);

        lg2::debug("serial={SERIAL} time={ETIME} nFields={NFIELDS}", "SERIAL",
                   serial, "ETIME", eventTime, "NFIELDS", nFields);

        int fieldIdx = 0;
        int frc;
        do
        {
            fieldIdx++;
            /* can return nullptr */
            const char* fieldName = auparse_get_field_name(au);
            const char* fieldTxt = auparse_get_field_str(au);

            lg2::debug("Field {NFIELD} : {FIELDNAME} = {FIELDSTR}", "NFIELD",
                       fieldIdx, "FIELDNAME", fieldName, "FIELDSTR", fieldTxt);
        } while ((frc = auparse_next_field(au)) == 1);
    }

    lg2::debug("type={RECTYPE}", "RECTYPE", recType);

    auto recMsg = auparse_get_record_text(au);

    lg2::debug("Record Msg={TEXT}", "TEXT", recMsg);

    /* Straight dump of record text to parsedFile */
    parsedFile << recMsg << '\n';

    return;
}

bool ALParser::openParsedFile(std::string filePath)
{
    std::error_code ec;

    // Check if file already exists. Error out.
    if (std::filesystem::exists(filePath, ec))
    {
#if 0
                lg2::error("File {FILE} already exists. ec: {EC}", "FILE",
                filePath, "EC", ec);
#else
        lg2::error("File {FILE} already exists.", "FILE", filePath);
#endif

        return false;
    }

    // Create/Open file using trunc
    parsedFile.open(filePath, std::ios::trunc);
    if (parsedFile.fail())
    {
        lg2::error("Failed to open {FILE}", "FILE", filePath);
        return false;
    }

    // Set permissions on file created, 600
    std::filesystem::perms permission = std::filesystem::perms::owner_read |
                                        std::filesystem::perms::owner_write;
    std::filesystem::permissions(filePath, permission);

    return true;
}

} // namespace auditlog
} // namespace phosphor
