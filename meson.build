project('bgpscanner', 'c', version : '2.31',
                          meson_version : '>=0.46.0',
                          license : 'BSD3',
                          default_options : [ 'c_std=c11', 'b_ndebug=if-release' ])

threads_dep = dependency('threads')
isocore_dep = dependency('isocore', fallback : [ 'isocore', 'isocore_dep' ])

if host_machine.system() == 'darwin'
	add_project_arguments(
		'-D_LARGEFILE_SOURCE',
		'-D_LARGEFILE64_SOURCE',
		'-D_FILE_OFFSET_BITS=64',
		'-D_POSIX_C_SOURCE=200809L',
		'-D_XOPEN_SOURCE=500',
		'-D_DARWIN_C_SOURCE',
		language : 'c'
	)
else
	add_project_arguments(
		'-D_LARGEFILE_SOURCE',
		'-D_LARGEFILE64_SOURCE',
		'-D_FILE_OFFSET_BITS=64',
		'-D_POSIX_C_SOURCE=200809L',
		'-D_XOPEN_SOURCE=500',
		language : 'c'
	)
endif

bgpscanner = executable('bgpscanner',
    sources : [
        'src/main.c',
        'src/mrtdataread.c'
    ],
    dependencies : [ isocore_dep, threads_dep ],
    install : true
)

install_man('bgpscanner.1')
