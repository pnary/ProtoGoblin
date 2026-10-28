project('protogoblin-io-cache', ['c', 'cpp'],
  version : '1.0.0',
  meson_version : '>= 0.49',
  default_options : [
    'cpp_std=c++17',
    'warning_level=1',
  ]
)

cpp = meson.get_compiler('cpp')

dl_dep = cpp.find_library('dl', required : false)
pthread_dep = dependency('threads')

src = files([
  'io_cache.cpp',
])

shared_library('protogoblin_io_cache',
  src,
  dependencies : [dl_dep, pthread_dep],
  install : true,
)
