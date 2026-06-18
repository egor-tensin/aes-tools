set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(aesxx INTERFACE)
target_include_directories(aesxx INTERFACE include/)
target_link_libraries(aesxx INTERFACE aes dbghelp)

if(MSVC_VERSION EQUAL 1900)
    # These annoying dbghelp.h warnings:
    # https://connect.microsoft.com/VisualStudio/feedback/details/888527/warnings-on-dbghelp-h
    target_compile_options(aesxx INTERFACE /wd4091)
endif()

install(DIRECTORY include/aesxx DESTINATION include)

add_subdirectory(utils)
