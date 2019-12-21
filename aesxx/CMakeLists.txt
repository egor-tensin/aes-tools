find_package(Boost REQUIRED)

add_library(aesxx INTERFACE)
target_include_directories(aesxx INTERFACE include/)
target_link_libraries(aesxx INTERFACE aes Boost::boost)

if(MSVC_VERSION EQUAL 1900)
    # These annoying DbgHelp.h warnings:
    # https://connect.microsoft.com/VisualStudio/feedback/details/888527/warnings-on-dbghelp-h
    target_compile_options(aesxx INTERFACE /wd4091)
endif()

install(DIRECTORY include/aesxx DESTINATION include)
