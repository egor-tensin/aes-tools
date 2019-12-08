project(aes_tools)

include(cmake/common.cmake)

set(AES_TOOLS_ASM OFF CACHE BOOL "Use the assembly language implementation instead of the one in C")

file(GLOB_RECURSE aes_include "include/*.h")

if(MSVC AND AES_TOOLS_ASM)
    enable_language(ASM_MASM)
    file(GLOB aes_src_c "src/*.c")
    file(GLOB aes_src_asm "src/asm/*.asm")
    set(aes_src ${aes_src_asm} ${aes_src_c})
    set_source_files_properties(${aes_src_asm} PROPERTIES COMPILE_FLAGS /safeseh)
    # Setting CMAKE_ASM_MASM_FLAGS doesn't work: http://www.cmake.org/Bug/view.php?id=14711
else()
    file(GLOB_RECURSE aes_src "src/*.c")
endif()

add_library(aes ${aes_src} ${aes_include})
target_include_directories(aes PUBLIC include/)

if(is_root_project)
    if(MSVC)
        target_compile_definitions(aes PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
endif()

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(aes PUBLIC -mssse3 -maes)
endif()

add_subdirectory(cxx)

add_subdirectory(utils)
