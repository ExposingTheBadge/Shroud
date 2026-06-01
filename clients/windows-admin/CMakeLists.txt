# shroud-admin — PRIVATE Windows operator client.
#
# DO NOT add this CMakeLists to the public release workflow. The output
# binary is NOT shipped in any user-facing release. See README.md and
# the user's standing instruction in
# ~/.claude/projects/D--APP-FuseOBD/memory/feedback-shroud-admin-private.md.

cmake_minimum_required(VERSION 3.16)
project(shroud_admin VERSION 2.6.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui Network)
find_package(Qt6 COMPONENTS WebSockets QUIET)
if(Qt6WebSockets_FOUND)
    add_compile_definitions(SHROUD_ADMIN_HAS_WS=1)
endif()

set(ADMIN_SOURCES
    main.cpp
    admin_window.cpp
    admin_client.cpp
    tabs/federation_tab.cpp
    tabs/stats_tab.cpp
    tabs/controls_tab.cpp
    tabs/logs_tab.cpp
    tabs/users_tab.cpp
    tabs/bans_tab.cpp
    tabs/diagnostics_tab.cpp
    tabs/manifest_tab.cpp
    tabs/relay_ssh_tab.cpp
    tabs/claude_chat_tab.cpp
    tabs/settings_tab.cpp
    tabs/errors_tab.cpp
    tabs/devices_tab.cpp
    tabs/audit_tab.cpp
    tabs/user_detail_dialog.cpp
    tabs/identity_tab.cpp
    tabs/backup_tab.cpp
    tabs/multisig_tab.cpp
    sparkline_widget.cpp
    oauth_helper.cpp
)

set(ADMIN_HEADERS
    admin_window.h
    admin_client.h
    tabs/federation_tab.h
    tabs/stats_tab.h
    tabs/controls_tab.h
    tabs/logs_tab.h
    tabs/users_tab.h
    tabs/bans_tab.h
    tabs/diagnostics_tab.h
    tabs/manifest_tab.h
    tabs/relay_ssh_tab.h
    tabs/claude_chat_tab.h
    tabs/settings_tab.h
    tabs/errors_tab.h
    tabs/devices_tab.h
    tabs/audit_tab.h
    tabs/user_detail_dialog.h
    tabs/identity_tab.h
    tabs/backup_tab.h
    tabs/multisig_tab.h
    sparkline_widget.h
    oauth_helper.h
)

add_executable(shroud-admin
    ${ADMIN_SOURCES}
    ${ADMIN_HEADERS}
    shroud_admin.qrc
)

target_include_directories(shroud-admin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/tabs
)

target_link_libraries(shroud-admin PRIVATE
    Qt6::Widgets Qt6::Core Qt6::Gui Qt6::Network
    crypt32
)
if(Qt6WebSockets_FOUND)
    target_link_libraries(shroud-admin PRIVATE Qt6::WebSockets)
endif()

target_compile_definitions(shroud-admin PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN
    SHROUD_ADMIN_VERSION="${PROJECT_VERSION}"
)
set_target_properties(shroud-admin PROPERTIES WIN32_EXECUTABLE TRUE)
