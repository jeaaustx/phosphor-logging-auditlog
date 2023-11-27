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

extra_args = []
# extra_args += ['-DAUDITLOG_FULL_DEBUG',]

executable('phosphor-auditlog',
    auditlog_sources,
    include_directories: include_directories('..'),
    cpp_args: extra_args,
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
