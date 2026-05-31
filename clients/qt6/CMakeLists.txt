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
