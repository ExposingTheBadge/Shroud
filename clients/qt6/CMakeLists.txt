# ─────────────────────────────────────────────────────────────────────
#  DEPRECATED — superseded by clients/windows/. DO NOT SHIP THIS.
#
#  This is a stale parallel copy of the Windows client, last updated at
#  v1.2.0 while clients/windows/ is at 2.6.6. Its main.cpp is 700 lines
#  against that one's 3287 and predates anonymous routing entirely, so a
#  binary built here talks to the legacy /messages/send path and violates
#  Rule 1 and Rule 2. No workflow, script or document references it.
#
#  It also stopped linking: it compiles ../windows/crypto.c, which has
#  since grown a dependency on ratchet_hkdf_sha512 from ratchet.c, and
#  this module list never followed. ratchet.c is listed below purely so
#  the tree contains no broken build — not as an endorsement of building
#  it. Delete this directory when convenient.
# ─────────────────────────────────────────────────────────────────────
cmake_minimum_required(VERSION 3.16)
project(SHROUD VERSION 1.2.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui Network)

# Windows crypto/network modules
set(WIN_MODULES
    ../windows/crypto.c
    ../windows/network.c
    ../windows/storage.c
    ../windows/tpm.c
    ../windows/kyber1024.c
    ../windows/ratchet.c      # crypto.c needs ratchet_hkdf_sha512
)

add_executable(shroud
    main.cpp
    ${WIN_MODULES}
)

target_include_directories(shroud PRIVATE
    ../windows
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(shroud PRIVATE
    Qt6::Widgets
    Qt6::Core
    Qt6::Gui
    Qt6::Network
    bcrypt ncrypt winhttp ws2_32 crypt32 tbs user32 gdi32 advapi32 comdlg32 shell32 dwmapi uxtheme
)

target_compile_definitions(shroud PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
set_target_properties(shroud PROPERTIES WIN32_EXECUTABLE TRUE)
