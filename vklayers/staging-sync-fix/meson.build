project('staging-sync-fix', ['c', 'cpp'],
  version : '1.0.0',
  meson_version : '>= 0.49',
  default_options : [
    'cpp_std=c++17',
    'warning_level=1',
  ]
)

cpp = meson.get_compiler('cpp')

compiler_args = [
  '-DNOMINMAX',
  '-D_WIN32_WINNT=0x0601',
]

link_args = [
  '-static',
  '-static-libgcc',
  '-static-libstdc++',
  '-Wl,--file-alignment=4096',
]

add_project_arguments(cpp.get_supported_arguments(compiler_args), language : ['c', 'cpp'])
add_project_link_arguments(cpp.get_supported_link_arguments(link_args), language : ['c', 'cpp'])

src = files([
  'main.cpp',
  'impl.cpp',
])

d3d11_dll = shared_library('d3d11',
  src,
  name_prefix : '',
  install : true,
  vs_module_defs : 'd3d11.def',
)
