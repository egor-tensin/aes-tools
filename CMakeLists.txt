project(aes_tools)

if(MSVC)
    add_compile_options(/MP /W4)
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    add_compile_options(-Wall -Wextra)
endif()

get_directory_property(parent_directory PARENT_DIRECTORY)
set(is_root_project $<NOT:parent_directory>)

function(use_static_runtime_msvc target)
    target_compile_options(${target} PRIVATE
        $<$<CONFIG:Debug>:/MTd>
        $<$<CONFIG:Release>:/MT>)
endfunction()

function(use_static_runtime_gcc target)
    get_target_property(type ${target} TYPE)
    if(type STREQUAL EXECUTABLE)
        target_link_libraries(${target} PRIVATE -static)
    endif()
endfunction()

function(use_static_runtime target)
    if(MSVC)
        use_static_runtime_msvc(${target})
    elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
        use_static_runtime_gcc(${target})
    endif()
endfunction()

function(strip_symbol_table_gcc target)
    target_link_libraries(${target} PRIVATE $<$<CONFIG:Release>:-s>)
endfunction()

function(strip_symbol_table target)
    if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
        strip_symbol_table_gcc(${target})
    endif()
endfunction()

macro(add_executable target)
    _add_executable(${ARGV})
    if(TARGET ${target} AND is_root_project)
        use_static_runtime(${target})
        strip_symbol_table(${target})
    endif()
endmacro()

file(GLOB_RECURSE libaes_headers "include/*.h")

if(MSVC AND AES_TOOLS_ASM)
    enable_language(ASM_MASM)
    file(GLOB libaes_c_sources "src/*.c")
    file(GLOB libaes_asm_sources "src/asm/*.asm")
    set(libaes_sources ${libaes_asm_sources} ${libaes_c_sources})
    set_source_files_properties(${libaes_asm_sources} PROPERTIES COMPILE_FLAGS "/safeseh")
    # Setting CMAKE_ASM_MASM_FLAGS doesn't work: http://www.cmake.org/Bug/view.php?id=14711
else()
    file(GLOB_RECURSE libaes_sources "src/*.c")
endif()

add_library(libaes ${libaes_sources} ${libaes_headers})
target_include_directories(libaes PUBLIC include/)
use_static_runtime(libaes)

if(MSVC)
    target_compile_definitions(libaes PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(libaes PUBLIC -mssse3 -maes)
endif()

add_subdirectory(cxx)

add_subdirectory(utils)
