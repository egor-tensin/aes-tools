set(orig_dir "${CMAKE_CURRENT_SOURCE_DIR}/bmp")
set(test_dir "${CMAKE_CURRENT_SOURCE_DIR}/out")

add_test(
    NAME create_test_dir
    COMMAND ${CMAKE_COMMAND} -E make_directory "${test_dir}"
)
set_tests_properties(create_test_dir PROPERTIES FIXTURES_SETUP test_dir)
add_test(
    NAME remove_test_dir
    COMMAND ${CMAKE_COMMAND} -E rm -r -- "${test_dir}"
)
set_tests_properties(remove_test_dir PROPERTIES FIXTURES_CLEANUP test_dir)

set(args
    -a aes128
    -k 000102030405060708090a0b0c0d0e0f
    -v 11111111111111112222222222222222
)

foreach(mode ecb cbc)
    add_test(
        NAME "encrypt_bmp_${mode}"
        COMMAND util_encrypt_bmp ${args} -m "${mode}"
            -i "${orig_dir}/butterfly.bmp"
            -o "${test_dir}/cipherfly_${mode}.bmp"
    )
    set_tests_properties("encrypt_bmp_${mode}" PROPERTIES
        FIXTURES_REQUIRED test_dir
        FIXTURES_SETUP "encrypt_bmp_${mode}"
    )
    add_test(
        NAME "encrypt_bmp_${mode}_compare"
        COMMAND ${CMAKE_COMMAND} -E compare_files
            "${orig_dir}/cipherfly_${mode}.bmp"
            "${test_dir}/cipherfly_${mode}.bmp"
    )
    set_tests_properties("encrypt_bmp_${mode}_compare" PROPERTIES
        FIXTURES_REQUIRED "test_dir;encrypt_bmp_${mode}"
    )

    add_test(
        NAME "decrypt_bmp_${mode}"
        COMMAND util_decrypt_bmp ${args} -m "${mode}"
            -i "${test_dir}/cipherfly_${mode}.bmp"
            -o "${test_dir}/butterfly_${mode}.bmp"
    )
    set_tests_properties("decrypt_bmp_${mode}" PROPERTIES
        FIXTURES_REQUIRED test_dir
        FIXTURES_SETUP "decrypt_bmp_${mode}"
    )
    add_test(
        NAME "decrypt_bmp_${mode}_compare"
        COMMAND ${CMAKE_COMMAND} -E compare_files
            "${orig_dir}/butterfly.bmp"
            "${test_dir}/butterfly_${mode}.bmp"
    )
    set_tests_properties("decrypt_bmp_${mode}_compare" PROPERTIES
        FIXTURES_REQUIRED "test_dir;decrypt_bmp_${mode}"
    )
endforeach()
