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
endforeach()
