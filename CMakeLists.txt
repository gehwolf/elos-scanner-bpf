cmake_minimum_required(VERSION 3.18)

set(PLUGIN_VERSION_MAJOR 0)
set(PLUGIN_VERSION_MINOR 1)
set(PLUGIN_VERSION_MICRO 0)
set(PLUGIN_VERSION
    ${PLUGIN_VERSION_MAJOR}.${PLUGIN_VERSION_MINOR}.${PLUGIN_VERSION_MICRO})

project(elos-bpf-scanner VERSION ${PLUGIN_VERSION} LANGUAGES C)

set(CMAKE_C_STANDARD 17)
include(GNUInstallDirs)

find_package(safu 0.54.0 REQUIRED)
find_package(samconf 0.53.1 REQUIRED)
find_package(libelosplugin 1.0.0 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

set(ELOSD_SCANNER_PLUGIN_PATH ${CMAKE_INSTALL_LIBDIR}/elos/scanner/)

add_compile_options(-O3 -DNDEBUG -g)
add_subdirectory(src/bpf)
add_executable(bpf_project src/main.c src/bpf_program.c)
add_dependencies(bpf_project socket)
target_link_libraries(bpf_project ${LIBBPF_LIBRARIES} elf z)

add_library(scanner_bpf SHARED src/bpfScanner.c src/bpf_program.c)
set_target_properties(scanner_bpf PROPERTIES PREFIX "")
set_target_properties(scanner_bpf
    PROPERTIES SOVERSION ${PLUGIN_VERSION_MAJOR}
    VERSION ${PLUGIN_VERSION}
)

target_link_libraries(scanner_bpf
    PUBLIC elos::libelosplugin samconf::samconf safu::safu ${LIBBPF_LIBRARIES} elf z
)

install(TARGETS scanner_bpf DESTINATION ${ELOSD_SCANNER_PLUGIN_PATH})
