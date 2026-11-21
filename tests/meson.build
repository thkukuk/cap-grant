test_cap_grant = executable('test-cap-grant',
           'test-cap-grant.c',
           include_directories : inc,
           link_with : libcap_grant,
           install : false)

test('cap-grant-integration',
     find_program('run-integration-tests.sh'),
     env : ['BUILD_DIR=' + meson.project_build_root()],
     timeout : 60,
     is_parallel : false)
