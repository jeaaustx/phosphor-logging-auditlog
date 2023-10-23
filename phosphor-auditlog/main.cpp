#include "config.h"

#include "config_main.h"

#include "auditLogMgr.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>

// AUDITLOG_PATH
constexpr auto auditLogMgrRoot = "/xyz/openbmc_project/logging/auditlog";
// AUDITLOG_INTERFACE
constexpr auto auditLogBusName = "xyz.openbmc_project.logging.auditlog";

int main(int /*argc*/, char* /*argv*/[])
{
    auto bus = sdbusplus::bus::new_default();
    sdbusplus::server::manager_t objManager{bus, auditLogMgrRoot};

    // Reserve the dbus service name
    bus.request_name(auditLogBusName);

    phosphor::auditlog::ALManager alMgr(bus, auditLogMgrRoot);

    // Handle dbus processing forever.
    bus.process_loop();

    return 0;
}
