set(algorithms
    aes128
    aes192
)
set(modes
    ecb
    cbc
)

set(plaintexts
    00112233445566778899aabbccddeeff
    889b6b42db774ce1147a6659778c40e0
    00000000000000000000000000000000
)

set(init_vectors_ecb "" "" "")
set(init_vectors_cbc
    00000000000000000000000000000000
    11111111111111111111111111111111
    a1e6f520bade7165f07486a185c53de7
)

set(keys_aes128
    000102030405060708090a0b0c0d0e0f
    00000000000000000000000000000000
    59713bfd33668d766c23a5dc8961f112
)
set(ciphertexts_aes128_ecb
    69c4e0d86a7b0430d8cdb78070b4c55a
    69233b712f1c3429986f65725ef1d4e3
    ea3776a8de8c11dedfa228f185e0f639
)
set(ciphertexts_aes128_cbc
    69c4e0d86a7b0430d8cdb78070b4c55a
    d30635a430ec897ffa64539447ce219e
    2eef761f20842bb451799b56ac1b9731
)

set(keys_aes192
    000102030405060708090a0b0c0d0e0f1011121314151617
    000000000000000000000000000000000000000000000000
    a07857432a0e045446509c1dde49d05ce91da019d1917b67
)
set(ciphertexts_aes192_ecb
    dda97ca4864cdfe06eaf70a0ec0d7191
    5e4357a8e0f098948190fbd286641d9b
    183e763c8166fc52086a7b3e51bdd3d6
)
set(ciphertexts_aes192_cbc
    dda97ca4864cdfe06eaf70a0ec0d7191
    188bf0d78406d7edf03111539f0e5fd7
    ab0f7f0470888795722b302c51b91883
)

# Skipping AES256...

foreach(algorithm ${algorithms})
    foreach(mode ${modes})
        set(input "")
        foreach(blocks IN ZIP_LISTS "keys_${algorithm}" "init_vectors_${mode}" plaintexts)
            list(APPEND input -- "${blocks_0}")
            if(NOT "${blocks_1}" STREQUAL "")
                list(APPEND input "${blocks_1}")
            endif()
            list(APPEND input "${blocks_2}")
        endforeach()
        string(JOIN "\n" output ${ciphertexts_${algorithm}_${mode}})

        message(STATUS "Adding test for encrypt_block (${algorithm}/${mode})")
        add_test(NAME "util_encrypt_block_${algorithm}_${mode}"
            COMMAND Python3::Interpreter
                "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
                run
                --pass-regex "^${output}$"
                --
                "$<TARGET_FILE:util_encrypt_block>" -a "${algorithm}" -m "${mode}" ${input}
        )

        set(input "")
        foreach(blocks IN ZIP_LISTS "keys_${algorithm}" "init_vectors_${mode}" "ciphertexts_${algorithm}_${mode}")
            list(APPEND input -- "${blocks_0}")
            if(NOT "${blocks_1}" STREQUAL "")
                list(APPEND input "${blocks_1}")
            endif()
            list(APPEND input "${blocks_2}")
        endforeach()
        string(JOIN "\n" output ${plaintexts})

        message(STATUS "Adding test for decrypt_block (${algorithm}/${mode})")
        add_test(NAME "util_decrypt_block_${algorithm}_${mode}"
            COMMAND Python3::Interpreter
                "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
                run
                --pass-regex "^${output}$"
                --
                "$<TARGET_FILE:util_decrypt_block>" -a "${algorithm}" -m "${mode}" ${input}
        )
    endforeach()
endforeach()
