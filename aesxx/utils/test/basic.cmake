foreach(action encrypt decrypt)
    foreach(util block file bmp)
        set(exe "${action}_${util}")
        set(tgt "util_${exe}")
        add_test(NAME "${tgt}_help" COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
            run
            --pass-regex "usage: ${exe}\\.exe" "set algorithm"
            --fail-regex "usage error:"
            --
            "$<TARGET_FILE:${tgt}>" -h
        )
        add_test(NAME "${tgt}_no_args" COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
            run
            --exit-code 1
            --pass-regex
                "usage error: the option '--algorithm' is required"
                "usage: ${exe}\\.exe"
                "set algorithm"
            --
            "$<TARGET_FILE:${tgt}>"
        )
    endforeach()

    set(exe "${action}_block")
    set(tgt "util_${exe}")
    add_test(NAME "${tgt}_no_input" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --fail-regex ".+"
        --
        "$<TARGET_FILE:${tgt}>" -a aes256 -m ofb
    )
    add_test(NAME "${tgt}_only_key" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --fail-regex ".+"
        --
        "$<TARGET_FILE:${tgt}>" -a AES256 -m ECB 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    )
    add_test(NAME "${tgt}_invalid_algorithm" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex "usage error:" "for option '--algorithm' is invalid"
        --
        "$<TARGET_FILE:${tgt}>" -a bar -m ecb
    )
    add_test(NAME "${tgt}_invalid_mode" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex "usage error:" "for option '--mode' is invalid"
        --
        "$<TARGET_FILE:${tgt}>" -a aes128 -m foo
    )
    add_test(NAME "${tgt}_no_iv" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex "usage error: an initialization vector is required"
        --
        "$<TARGET_FILE:${tgt}>" -a aes192 -m cbc 000102030405060708090a0b0c0d0e0f1011121314151617
    )
    add_test(NAME "${tgt}_invalid_key1" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex [=[AES error: Couldn't parse '0001020304050607' \(possibly not complete input\) as a 32-byte hex string]=]
        --
        "$<TARGET_FILE:${tgt}>" -a aes256 -m ecb 0001020304050607
    )
    add_test(NAME "${tgt}_invalid_key2" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex [=[AES error: Couldn't parse 'foobar' \(possibly not complete input\) as a 32-byte hex string]=]
        --
        "$<TARGET_FILE:${tgt}>" -a aes256 -m ecb foobar
    )
    add_test(NAME "${tgt}_invalid_iv1" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex [=[AES error: Couldn't parse '2222222222222222222222222222222' \(possibly not complete input\) as a 16-byte hex string]=]
        --
        "$<TARGET_FILE:${tgt}>" -a aes128 -m cbc 11111111111111111111111111111111 2222222222222222222222222222222
    )
    add_test(NAME "${tgt}_invalid_iv2" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex [=[AES error: Couldn't parse '222222222222222222222222222222222' \(possibly not complete input\) as a 16-byte hex string]=]
        --
        "$<TARGET_FILE:${tgt}>" -a aes128 -m cbc 11111111111111111111111111111111 222222222222222222222222222222222
    )
    add_test(NAME "${tgt}_invalid_block" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex [=[AES error: Couldn't parse '0' \(possibly not complete input\) as a 16-byte hex string]=]
        --
        "$<TARGET_FILE:${tgt}>" -a aes128 -m cbc 11111111111111111111111111111111 22222222222222222222222222222222 0
    )

    set(exe "${action}_file")
    set(tgt "util_${exe}")
    add_test(NAME "${tgt}_no_key" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex [=[the option '--key' is required but missing]=]
        --
        "$<TARGET_FILE:${tgt}>" -a aes128 -m ecb -i in.txt -o out.txt
    )
    add_test(NAME "${tgt}_no_files" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --exit-code 1
        --pass-regex [=[the option '--input' is required but missing]=]
        --
        "$<TARGET_FILE:${tgt}>" -a aes128 -m ecb -k 11111111111111111111111111111111
    )
    add_test(NAME "${tgt}_no_iv" COMMAND Python3::Interpreter
        "${CMAKE_SOURCE_DIR}/cmake/tools/ctest-driver.py"
        run
        --
        "$<TARGET_FILE:${tgt}>" -a aes128 -m cbc -k 11111111111111111111111111111111 -i in.txt -o out.txt
    )
endforeach()
