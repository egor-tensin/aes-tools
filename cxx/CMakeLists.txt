find_package(Boost REQUIRED)

add_library(libaesxx INTERFACE)
target_include_directories(libaesxx INTERFACE include/ ${Boost_INCLUDE_DIRS})
target_link_libraries(libaesxx INTERFACE libaes)
