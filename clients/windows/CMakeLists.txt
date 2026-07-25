cmake_minimum_required(VERSION 3.16)

# Read the version from the repo's VERSION file rather than repeating it
# here. Keeping the two in step was a manual step in the release process
# and they drifted: VERSION said 2.6.7 while this line still said 2.6.6,
# so a freshly built client told the user "SHROUD v2.6.7 is available,
# you have v2.6.6" about itself. One source of truth removes the step.
set(SHROUD_VERSION "0.0.0")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION" SHROUD_VERSION)
    string(STRIP "${SHROUD_VERSION}" SHROUD_VERSION)
endif()
project(SHROUD VERSION ${SHROUD_VERSION} LANGUAGES CXX C)
message(STATUS "SHROUD client version: ${PROJECT_VERSION}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui Network)

# Crypto/network/storage modules
set(WIN_MODULES
    crypto.c
    network.c
    storage.c
    tpm.c
    kyber1024.c
    ratchet.c
    oqs_sig.c
    ed25519.c
    anon_routing.c
    error_reporter.c
)

add_executable(shroud
    main.cpp
    anon_client.cpp
    shroud.qrc
    shroud.rc
    ${WIN_MODULES}
)

target_include_directories(shroud PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(shroud PRIVATE
    Qt6::Widgets
    Qt6::Core
    Qt6::Gui
    Qt6::Network
    bcrypt ncrypt winhttp ws2_32 crypt32 tbs user32 gdi32 advapi32 comdlg32 shell32 dwmapi uxtheme dbghelp
)

target_compile_definitions(shroud PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN
    # Tie the runtime version string to project(SHROUD VERSION ...). The
    # release workflow only bumps VERSION + the CMake project() line; this
    # propagates the bump into the binary without any extra hand-edit step.
    CLIENT_VERSION="${PROJECT_VERSION}"
)
set_target_properties(shroud PROPERTIES WIN32_EXECUTABLE TRUE)
