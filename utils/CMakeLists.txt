add_subdirectory(cxx)

macro(util prefix)
    add_executable(util_${prefix} ${prefix}.cpp)
    target_link_libraries(util_${prefix} libaesnixx libaesni)
    set_target_properties(util_${prefix} PROPERTIES OUTPUT_NAME ${prefix})
endmacro()

util(aes128ecb_encrypt_file)
util(aes128ecb_decrypt_file)
