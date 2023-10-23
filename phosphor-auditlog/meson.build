auditd_dep = dependency('audit')
ausparse_dep = cpp.find_library('libauparse', required: true)

auditlog_sources = [
        files(
        'main.cpp',
        'auditLogMgr.cpp',
        'auditLogParser.cpp',
        'auditLogUtils.cpp',
        )
]
executable('phosphor-auditlog',
    auditlog_sources,
    include_directories: include_directories('..'),
    dependencies: [
        conf_h_dep,
        phosphor_logging_dep,
        pdi_dep,
        sdbusplus_dep,
        sdeventplus_dep,
        auditd_dep,
        ausparse_dep,
    ],
    install: true,
)
