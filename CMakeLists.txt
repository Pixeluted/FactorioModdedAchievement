cmake_minimum_required(VERSION 3.31)
project(FactorioModdedAchievement)

set(CMAKE_CXX_STANDARD 20)
add_compile_definitions(_NO_CVCONST_H)

add_library(${PROJECT_NAME} SHARED Entry.cpp
        Proxy.hpp)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/MinHook")

target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/MinHook/include")
target_link_libraries(${PROJECT_NAME} PUBLIC
        dbghelp.lib
        minhook
)