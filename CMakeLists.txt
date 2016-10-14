project(aes_tools)

if(MSVC)
    add_compile_options(/MP /W4)
elseif(CMAKE_COMPILER_IS_GNUCC)
    add_compile_options(-Wall -Wextra)
endif()

file(GLOB_RECURSE libaes_headers "include/*.h")

if(MSVC AND LIBAES_USE_ASM)
    enable_language(ASM_MASM)

    file(GLOB libaes_c_sources "src/*.c")
    file(GLOB libaes_asm_sources "src/asm/*.asm")

    set(libaes_sources ${libaes_asm_sources} ${libaes_c_sources})
    set_source_files_properties(${libaes_asm_sources} PROPERTIES COMPILE_FLAGS "/safeseh")
    # Setting CMAKE_ASM_MASM_FLAGS doesn't work: http://www.cmake.org/Bug/view.php?id=14711
else()
    file(GLOB_RECURSE libaes_sources "src/*.c")
endif()

if(CMAKE_COMPILER_IS_GNUCC)
    add_compile_options(-mssse3 -maes)
endif()

add_library(libaes ${libaes_sources} ${libaes_headers})
target_include_directories(libaes PUBLIC include/)
if(MSVC)
    target_compile_definitions(libaes PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

add_subdirectory(cxx)

add_subdirectory(utils)
