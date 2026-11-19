# Fuzz targets (see fuzz-targets.cmake). MAYHEM_FUZZ_LINK selects the driver: the libFuzzer engine
# (-fsanitize=fuzzer) or the standalone run-once main object (MAYHEM_STANDALONE_OBJ), for a
# "<name>" and a "<name>-standalone" binary. MAYHEM_LSAN_OFF_OBJ (mayhem/lsan_off.cc) goes into both.
set(MAYHEM_FUZZERS
  fuzz_server_proxy
  fuzz_client_proxy
  fuzz_clipboard_unmarshall
  fuzz_clipboard_chunk
  fuzz_unicode
  fuzz_keyboard_layouts
  fuzz_server_config
  fuzz_fingerprint_db
)
set(_mayhem_dir "${CMAKE_SOURCE_DIR}/mayhem")
foreach(f IN LISTS MAYHEM_FUZZERS)
  foreach(variant IN ITEMS "" "-standalone")
    set(t "${f}${variant}")
    add_executable(${t} "${_mayhem_dir}/harnesses/${f}.cpp")
    target_include_directories(${t} PRIVATE "${_mayhem_dir}/harnesses")
    target_link_libraries(${t} PRIVATE
      client server app net platform io mt base arch common
      Qt6::Core Qt6::Network
      "${MAYHEM_LSAN_OFF_OBJ}"
    )
    if(variant STREQUAL "")
      target_link_options(${t} PRIVATE ${MAYHEM_FUZZ_ENGINE})
    else()
      target_link_libraries(${t} PRIVATE "${MAYHEM_STANDALONE_OBJ}")
    endif()
    set_target_properties(${t} PROPERTIES EXCLUDE_FROM_ALL TRUE RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz")
  endforeach()
endforeach()
