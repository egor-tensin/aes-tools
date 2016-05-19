project(aes_tools C CXX ASM_MASM)

file(GLOB_RECURSE libaes_headers "include/*.h")
if(AESNI_USE_ASM)
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
target_compile_definitions(libaes PRIVATE _CRT_SECURE_NO_WARNINGS)

add_subdirectory(cxx)

add_subdirectory(utils)
