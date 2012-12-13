from distutils.core import setup, Extension

module = Extension('_lxc', sources=['lxc.c'], libraries=['lxc'])

setup(name='_lxc',
      version='0.1',
      description='LXC',
      packages=['lxc'],
      package_dir={'lxc': 'lxc'},
      ext_modules=[module])
