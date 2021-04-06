cmake_minimum_required(VERSION 3.5) # for Boost::* imported targets

project(aes_tools C CXX)
enable_testing()

include(cmake/common.cmake)

add_subdirectory(aes)
add_subdirectory(aesxx)
add_subdirectory(test)

install(FILES LICENSE.txt DESTINATION share)
