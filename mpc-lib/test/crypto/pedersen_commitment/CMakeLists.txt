add_executable(pedersen_commitment_test
    tests.cpp
)

target_compile_options(pedersen_commitment_test PRIVATE -Wall -Wextra)
target_link_libraries(pedersen_commitment_test PRIVATE tests_main)

add_test(NAME pedersen_commitment_test COMMAND pedersen_commitment_test)
