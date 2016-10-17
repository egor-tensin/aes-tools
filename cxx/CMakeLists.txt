find_package(Boost REQUIRED)

add_library(libaesxx INTERFACE)
target_include_directories(libaesxx INTERFACE include/)
target_include_directories(libaesxx SYSTEM INTERFACE ${Boost_INCLUDE_DIRS})
target_link_libraries(libaesxx INTERFACE libaes)

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(libaesxx INTERFACE -std=c++11)
endif()
