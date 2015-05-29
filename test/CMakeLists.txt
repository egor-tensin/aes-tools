set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO")

macro(test prefix)
    add_executable(${prefix}_encrypt_block ${prefix}_encrypt_block.c)
    target_link_libraries(${prefix}_encrypt_block libaesni)

    add_executable(${prefix}_decrypt_block ${prefix}_decrypt_block.c)
    target_link_libraries(${prefix}_decrypt_block libaesni)
endmacro()

test(aes128ecb)
test(aes192ecb)
test(aes256ecb)
test(aes256cbc)