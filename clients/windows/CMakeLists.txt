cmake_minimum_required(VERSION 3.16)
project(SHROUD VERSION 2.5.0 LANGUAGES CXX C)

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

target_compile_definitions(shroud PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
set_target_properties(shroud PROPERTIES WIN32_EXECUTABLE TRUE)
