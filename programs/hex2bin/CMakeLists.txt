ADD_EXECUTABLE(hex2bin hex2bin.cc)

ADD_TEST(hex2bin-test ${PYTHON_EXE} ${CMAKE_CURRENT_SOURCE_DIR}/hex2bin_test.py)
