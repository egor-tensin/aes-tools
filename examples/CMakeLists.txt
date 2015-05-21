set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO")

macro(example prefix)
    add_executable(${prefix}_example ${prefix}_example.c)
    target_link_libraries(${prefix}_example libaesni)
endmacro()

example(aes128)
example(aes192)
example(aes256ecb)
example(aes256cbc)
