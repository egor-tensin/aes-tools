project(aes_tools)

get_directory_property(parent_directory PARENT_DIRECTORY)
set(is_root_project $<NOT:parent_directory>)

set(AES_TOOLS_USE_STATIC_RUNTIME "${is_root_project}" CACHE BOOL "Link the runtime statically")
set(AES_TOOLS_STRIP_SYMBOL_TABLE "${is_root_project}" CACHE BOOL "Strip symbol tables")

set(AES_TOOLS_ASM OFF CACHE BOOL "Use the assembly language implementation instead of the one in C")

if(is_root_project)
    if(MSVC)
        add_compile_options(/MP /W4)
    elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
        add_compile_options(-Wall -Wextra)
    endif()
endif()

function(use_static_runtime_msvc target)
    target_compile_options("${target}" PRIVATE
        $<$<CONFIG:Debug>:/MTd>
        $<$<NOT:$<CONFIG:Debug>>:/MT>)
endfunction()

function(use_static_runtime_gcc target)
    get_target_property(target_type "${target}" TYPE)
    if(target_type STREQUAL EXECUTABLE)
        target_link_libraries("${target}" PRIVATE -static)
    endif()
endfunction()

function(use_static_runtime target)
    if(MSVC)
        use_static_runtime_msvc("${target}")
    elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
        use_static_runtime_gcc("${target}")
    else()
        message(WARNING "Unrecognized toolset")
    endif()
endfunction()

function(strip_symbol_table_gcc target)
    target_link_libraries("${target}" PRIVATE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-s>)
endfunction()

function(strip_symbol_table target)
    if(MSVC)
    elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
        strip_symbol_table_gcc("${target}")
    else()
        message(WARNING "Unrecognized toolset")
    endif()
endfunction()

macro(add_executable target)
    _add_executable(${ARGV})
    if(TARGET "${target}")
        if(AES_TOOLS_USE_STATIC_RUNTIME)
            use_static_runtime("${target}")
        endif()
        if(AES_TOOLS_STRIP_SYMBOL_TABLE)
            strip_symbol_table("${target}")
        endif()
    endif()
endmacro()

file(GLOB_RECURSE libaes_headers "include/*.h")

if(MSVC AND AES_TOOLS_ASM)
    enable_language(ASM_MASM)
    file(GLOB libaes_c_sources "src/*.c")
    file(GLOB libaes_asm_sources "src/asm/*.asm")
    set(libaes_sources ${libaes_asm_sources} ${libaes_c_sources})
    set_source_files_properties(${libaes_asm_sources} PROPERTIES COMPILE_FLAGS /safeseh)
    # Setting CMAKE_ASM_MASM_FLAGS doesn't work: http://www.cmake.org/Bug/view.php?id=14711
else()
    file(GLOB_RECURSE libaes_sources "src/*.c")
endif()

add_library(libaes ${libaes_sources} ${libaes_headers})
target_include_directories(libaes PUBLIC include/)

if(AES_TOOLS_USE_STATIC_RUNTIME)
    use_static_runtime(libaes)
endif()

if(is_root_project)
    if(MSVC)
        target_compile_definitions(libaes PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
endif()

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(libaes PUBLIC -mssse3 -maes)
endif()

add_subdirectory(cxx)

add_subdirectory(utils)
