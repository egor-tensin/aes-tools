add_library(libaesnixx INTERFACE)
target_include_directories(libaesnixx INTERFACE include/)
target_link_libraries(libaesnixx INTERFACE libaesni)
