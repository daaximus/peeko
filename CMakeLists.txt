cmake_minimum_required(VERSION 3.9)
project(peeko C ASM)

set(CMAKE_C_STANDARD 99)

#
# thanks dude719 for making my life easy with
# his premade cmakelists.
#
# Get the MSYS path
if (WIN32)
    message(STATUS "We are on Win32!")
    set(HOST_OS "WIN32")
    set(MSYS_PATH)
    set(MSYS_PROGRAM_PATH)
    list(APPEND CMAKE_MSYS_PATHS "D:/msys64")
    foreach(MSYS_PATH_ELEMENT IN LISTS CMAKE_MSYS_PATHS)
        if (EXISTS ${MSYS_PATH_ELEMENT})
            set(MSYS_PATH ${MSYS_PATH_ELEMENT})
            break()
        endif(EXISTS ${MSYS_PATH_ELEMENT})
    endforeach(MSYS_PATH_ELEMENT)
    if (NOT MSYS_PATH)
        message(FATAL_ERROR "No MSYS_PATH or MINGW_PATH found!!")
    endif(NOT MSYS_PATH)
else()
    message(FATAL_ERROR "Platform not supported!")
endif()

if (HOST_OS STREQUAL "WIN32")
    #if (MSYS_PATH)
    #    # Get the MSYS /usr/bin path
    #    set(MSYS_PROGRAM_PATH "${MSYS_PATH}/usr/bin")
    #    message(STATUS "MSYS_PROGRAM_PATH=${MSYS_PROGRAM_PATH}")
    #    set(CLANG "${MSYS_PATH}/mingw64/bin/clang.exe")
    #    set(CLANGXX "${MSYS_PATH}/mingw64/bin/clang++.exe")
    #    # Use the Clang compiler!
    #    set(CMAKE_C_COMPILER ${CLANG})
    #    set(CMAKE_CXX_COMPILER ${CLANGXX})
    #endif(MSYS_PATH)
else()
    # Find the Clang compilers
    find_program(CLANG clang)
    find_program(CLANGXX clang++)
    if (NOT CLANG OR NOT CLANGXX)
        message(WARNING "Clang compiler not found!")
        find_program(GCC gcc)
        find_program(GXX g++)
        if (NOT GCC OR NOT GXX)
            message(FATAL_ERROR "Clang compiler not found!")
        else(NOT GCC OR NOT GXX)
            set(CMAKE_C_COMPILER "${GCC}")
            set(CMAKE_CXX_COMPILER "${GXX}")
        endif(NOT GCC OR NOT GXX)
    else(NOT CLANG OR NOT CLANGXX)
        set(CMAKE_C_COMPILER "${CLANG}")
        set(CMAKE_CXX_COMPILER "${CLANGXX}")
    endif(NOT CLANG OR NOT CLANGXX)
endif()

# Use the NASM compiler
set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
enable_language(ASM_NASM)
if(NOT CMAKE_ASM_NASM_COMPILER_LOADED)
    message(FATAL_ERROR "NASM assembler not found!")
endif(NOT CMAKE_ASM_NASM_COMPILER_LOADED)
# Add the -l listing file option
set(CMAKE_ASM_NASM_COMPILE_OBJECT "<CMAKE_ASM_NASM_COMPILER> <INCLUDES> <FLAGS> -f ${CMAKE_ASM_NASM_OBJECT_FORMAT} -o <OBJECT> <SOURCE>")
set(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")

set(CMAKE_C_FLAGS_INIT "-Wall -std=c99")
set(CMAKE_C_FLAGS_DEBUG_INIT "-g")
set(CMAKE_C_FLAGS_MINSIZEREL_INIT "-Os -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE_INIT "-O4 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO_INIT "-O2 -g")

#
# disabled warnings for -Wint-to-void-pointer-cast
# disabled warnings for -Wint-to-pointer-cast
#
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pointer-to-int-cast -Wno-int-to-void-pointer-cast -Wno-int-to-pointer-cast")
message(STATUS "CMAKE_C_FLAGS=${CMAKE_C_FLAGS}")

add_executable(peeko src/main.c src/pkoi.c src/asm/ntos.asm src/pkortl.c include)