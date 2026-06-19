# oldstable as of May '26
# Plus, I'm pretty sure it's required for things like CONFIGURE_DEPENDS and
# CMAKE_MSVC_RUNTIME_LIBRARY and stuff.
cmake_minimum_required(VERSION 3.25)

project(aes_tools C CXX ASM)
enable_testing()

if (MSVC)
    add_compile_options("$<$<NOT:$<COMPILE_LANGUAGE:ASM,ASM_MASM>>:/MP;/W4;/WX>")
else()
    add_compile_options("$<$<NOT:$<COMPILE_LANGUAGE:ASM,ASM_MASM>>:-Wall;-Wextra;-pedantic;-Werror>")
endif()

add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX)

add_subdirectory(aes)
add_subdirectory(aesxx)
add_subdirectory(test)

install(FILES LICENSE.txt DESTINATION share)
