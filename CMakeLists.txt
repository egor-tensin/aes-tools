cmake_minimum_required(VERSION 3.5) # for Boost::* imported targets

project(aes_tools C CXX)

include(cmake/cmake/common.cmake)

add_subdirectory(aes)
add_subdirectory(aesxx)

install(FILES LICENSE.txt DESTINATION share)
