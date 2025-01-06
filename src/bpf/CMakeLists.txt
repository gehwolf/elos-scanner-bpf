find_program(CLANG_EXECUTABLE clang REQUIRED)

function(add_bpf_program target_name source_file)
    set(output_file "${CMAKE_BINARY_DIR}/${target_name}.bpf.o")

    if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        set(target_arch "x86")
    elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        set(target_arch "arm64")
    else ()
        message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif ()

    add_custom_command(
        OUTPUT ${output_file}
        COMMAND ${CLANG_EXECUTABLE}
        -O2 -g -target bpf -DBPF_NO_BTF
        -D__TARGET_ARCH_${target_arch}
        -c ${source_file}
        -o ${output_file}
        COMMENT "Compiling BPF program: ${source_file} -> ${output_file}"
        DEPENDS ${source_file}
    )


    set(${target_name}_OUTPUT ${output_file} PARENT_SCOPE)
    
    # skeletons are currently not used, keep it for reference and further experiments
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target_name}.skel.h
        COMMAND bpftool gen skeleton ${output_file} > ${CMAKE_CURRENT_BINARY_DIR}/${target_name}.skel.h
        DEPENDS ${output_file}
        COMMENT "Generating BPF skeleton for socket.bpf.o"
    )

    add_custom_target(${target_name} ALL DEPENDS ${output_file} ${CMAKE_CURRENT_BINARY_DIR}/${target_name}.skel.h)
    install(
        FILES
        ${output_file}
      DESTINATION
      ${ELOSD_SCANNER_PLUGIN_PATH}
      PERMISSIONS
          OWNER_READ OWNER_EXECUTE OWNER_WRITE
          GROUP_READ GROUP_EXECUTE GROUP_WRITE
          WORLD_READ WORLD_EXECUTE
    )
endfunction()

add_bpf_program(socket ${CMAKE_SOURCE_DIR}/src/bpf/socket.bpf.c)
add_bpf_program(minimal ${CMAKE_SOURCE_DIR}/src/bpf/minimal.bpf.c)
