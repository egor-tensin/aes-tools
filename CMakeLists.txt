project(aesni C CXX ASM_MASM)

file(GLOB_RECURSE libaesni_headers "include/*.h")
if(AESNI_USE_ASM)
    file(GLOB libaesni_c_sources "src/*.c")
    file(GLOB libaesni_asm_sources "src/asm/*.asm")
    set(libaesni_sources ${libaesni_asm_sources} ${libaesni_c_sources})
    set_source_files_properties(${libaesni_asm_sources} PROPERTIES COMPILE_FLAGS "/safeseh")
    # Setting CMAKE_ASM_MASM_FLAGS doesn't work: http://www.cmake.org/Bug/view.php?id=14711
else()
    file(GLOB_RECURSE libaesni_sources "src/*.c")
endif()
add_library(libaesni ${libaesni_sources} ${libaesni_headers})
target_include_directories(libaesni PUBLIC include/)
target_compile_definitions(libaesni PRIVATE _CRT_SECURE_NO_WARNINGS)

add_subdirectory(cxx)

add_subdirectory(examples)
add_subdirectory(utils)
