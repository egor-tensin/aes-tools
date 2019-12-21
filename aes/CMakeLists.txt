option(AES_TOOLS_ASM "Use the assembly language implementation instead of the one in C")

file(GLOB_RECURSE aes_include "include/*.h")
file(GLOB aes_src "src/*.c")

if(MSVC AND AES_TOOLS_ASM)
    enable_language(ASM_MASM)
    file(GLOB aes_src_impl "src/asm/*.asm")
    set_source_files_properties(${aes_src_impl} PROPERTIES COMPILE_FLAGS /safeseh)
    # Setting CMAKE_ASM_MASM_FLAGS doesn't work: http://www.cmake.org/Bug/view.php?id=14711
else()
    file(GLOB aes_src_impl "src/c/*.c")
endif()

add_library(aes ${aes_include} ${aes_src} ${aes_src_impl})
target_include_directories(aes PUBLIC include/)

if(MSVC)
    target_compile_definitions(aes PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(aes PUBLIC -mssse3 -maes)
endif()

install(TARGETS aes ARCHIVE DESTINATION lib)
install(DIRECTORY include/aes DESTINATION include)
