project(
  'cap-grant',
  'c',
  meson_version : '>= 0.61.0',
  default_options : [
                  'prefix=/usr',
                  'sysconfdir=/etc',
                  'localstatedir=/var',
                  'buildtype=debugoptimized',
  		  'default_library=shared',
		  'b_pie=true',
                  'b_lto=true',
		  'warning_level=2'],
  license : ['GPL-2.0-or-later', 'LGPL-2.1-or-later'],
  version : '0.1.0',
)

conf = configuration_data()
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('PACKAGE', meson.project_name())

cc = meson.get_compiler('c')
pkg = import('pkgconfig')
inc = include_directories(['include'])

add_project_arguments(['-D_GNU_SOURCE=1',
		       '-DXTSTRINGDEFINES',
		       '-D_FORTIFY_SOURCE=2',
                       '-D_FILE_OFFSET_BITS=64',
                       '-D_TIME_BITS=64'], language : 'c')

possible_cc_flags = [
		  '-fstack-protector-strong',
		  '-funwind-tables',
		  '-fasynchronous-unwind-tables',
		  '-fstack-clash-protection',
		  '-Werror=return-type',
		  '-Wbad-function-cast',
		  '-Wcast-align',
		  '-Wcast-qual',
                  '-Wformat-security',
		  '-Winline',
		  '-Wmissing-declarations',
		  '-Wmissing-prototypes',
		  '-Wnested-externs',
		  '-Wshadow',
		  '-Wstrict-prototypes',
		  '-Wundef',
		  ]
add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language : 'c')

# Meson ignores the preceding arguments when joining paths if an absolute
# component is encountered, so this should canonicalize various paths when they
# are absolute or relative.
prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif
libexecdir = join_paths(prefixdir, get_option('libexecdir'))
datadir = join_paths(prefixdir, get_option('datadir'))
systemunitdir = prefixdir / 'lib/systemd/system'
tmpfilesdir = prefixdir / 'lib/tmpfiles.d'

#libaudit = dependency('audit', required : get_option('audit'))
#conf.set10('HAVE_AUDIT', libaudit.found())

libsystemd = dependency('libsystemd', version: '>= 257', required : true)

libcap_grant_c = files('lib/cap-grant.c')
libcap_grant_map = 'lib/libcap-grant.map'
libcap_grant_map_version = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), libcap_grant_map)

libcap_grant = shared_library(
  'cap-grant',
  libcap_grant_c,
  include_directories : inc,
  link_args : ['-shared',
               libcap_grant_map_version],
  link_depends : libcap_grant_map,
  dependencies : [libsystemd],
  install : true,
  version : meson.project_version(),
  soversion : '0'
)
install_headers('include/cap-grant.h')

pkg.generate(
  libcap_grant,
  name : 'libcap-grant',
  description : 'library to record all logins and logouts',
  version : meson.project_version(),
)

cap_grantd_c = ['src/cap-grantd.c', 'src/cap-grantd-polkit.c', 'src/varlink-org.openSUSE.cap-grant.c', 'src/log_msg.c', 'src/mkdir_p.c']

executable('cap-grantd',
           cap_grantd_c,
           include_directories : inc,
           link_with : libcap_grant,
           dependencies : [libsystemd],
           install_dir : libexecdir,
           install : true)

subdir('examples')
subdir('systemd')
subdir('polkit')

# Unit tests
#subdir('tests')

# Manual pages
#subdir('man')

config_h = configure_file(
  output : 'config.h',
  configuration : conf)
