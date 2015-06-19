macro(util prefix)
    add_executable(util_${prefix} ${prefix}.cpp)
    target_link_libraries(util_${prefix} libaesnixx libaesni)
    set_target_properties(util_${prefix} PROPERTIES OUTPUT_NAME ${prefix})
endmacro()

util(aes128ecb_encrypt_file)
util(aes128ecb_decrypt_file)

find_package(Boost REQUIRED COMPONENTS program_options)

add_executable(util_encrypt_file_aes encrypt_file_aes.cpp common_aes.hpp)
target_include_directories(util_encrypt_file_aes PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_encrypt_file_aes libaesni libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_encrypt_file_aes PROPERTIES OUTPUT_NAME encrypt_file_aes)

add_executable(util_decrypt_file_aes decrypt_file_aes.cpp common_aes.hpp)
target_include_directories(util_decrypt_file_aes PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_decrypt_file_aes libaesni libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_decrypt_file_aes PROPERTIES OUTPUT_NAME decrypt_file_aes)
