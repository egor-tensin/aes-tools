macro(util prefix)
    add_executable(util_${prefix} ${prefix}.cpp)
    target_link_libraries(util_${prefix} libaesnixx libaesni)
    set_target_properties(util_${prefix} PROPERTIES OUTPUT_NAME ${prefix})
endmacro()

util(aes128ecb_encrypt_file)
util(aes128ecb_decrypt_file)

find_package(Boost REQUIRED COMPONENTS program_options)

add_executable(util_aes_encrypt_file aes_encrypt_file.cpp aes_common.hpp)
target_include_directories(util_aes_encrypt_file PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_aes_encrypt_file libaesni libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_aes_encrypt_file PROPERTIES OUTPUT_NAME aes_encrypt_file)

add_executable(util_aes_decrypt_file aes_decrypt_file.cpp aes_common.hpp)
target_include_directories(util_aes_decrypt_file PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_aes_decrypt_file libaesni libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_aes_decrypt_file PROPERTIES OUTPUT_NAME aes_decrypt_file)

add_executable(util_aes_encrypt_bmp aes_encrypt_bmp.cpp aes_common.hpp)
target_include_directories(util_aes_encrypt_bmp PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_aes_encrypt_bmp libaesni libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_aes_encrypt_bmp PROPERTIES OUTPUT_NAME aes_encrypt_bmp)

add_executable(util_aes_decrypt_bmp aes_decrypt_bmp.cpp aes_common.hpp)
target_include_directories(util_aes_decrypt_bmp PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(util_aes_decrypt_bmp libaesni libaesnixx ${Boost_LIBRARIES})
set_target_properties(util_aes_decrypt_bmp PROPERTIES OUTPUT_NAME aes_decrypt_bmp)
