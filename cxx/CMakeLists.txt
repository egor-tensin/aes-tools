find_package(Boost REQUIRED)

add_library(aesxx INTERFACE)
target_include_directories(aesxx INTERFACE include/)
target_include_directories(aesxx SYSTEM INTERFACE ${Boost_INCLUDE_DIRS})
target_link_libraries(aesxx INTERFACE aes)

if(MSVC_VERSION EQUAL 1900)
    # These annoying DbgHelp.h warnings:
    # https://connect.microsoft.com/VisualStudio/feedback/details/888527/warnings-on-dbghelp-h
    target_compile_options(aesxx INTERFACE /wd4091)
endif()
