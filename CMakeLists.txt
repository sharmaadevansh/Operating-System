cmake_minimum_required(VERSION 3.16)
project(IPCFramework CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ipc_server main.cpp)

target_link_libraries(ipc_server PRIVATE ws2_32)

# Copy dashboard to build dir
add_custom_command(TARGET ipc_server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/dashboard.html
        $<TARGET_FILE_DIR:ipc_server>/dashboard.html
)

# MSVC settings
if(MSVC)
    target_compile_options(ipc_server PRIVATE /W3 /MP)
    set_target_properties(ipc_server PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
endif()
