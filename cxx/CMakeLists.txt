find_package(Boost REQUIRED)

add_library(aesxx INTERFACE)
target_include_directories(aesxx INTERFACE include/)
target_include_directories(aesxx SYSTEM INTERFACE ${Boost_INCLUDE_DIRS})
target_link_libraries(aesxx INTERFACE aes)
