find_package(Boost REQUIRED)

add_library(libaesnixx INTERFACE)
target_include_directories(libaesnixx INTERFACE include/ ${Boost_INCLUDE_DIRS})
target_link_libraries(libaesnixx INTERFACE libaesni)
