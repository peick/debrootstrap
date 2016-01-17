import os
import subprocess
from cStringIO import StringIO
from textwrap import dedent
from flexmock import flexmock

import pytest

from debrootstrap import (
    Config,
    FileSystem,
    Package,
    Pattern,
    PatternList,
    PathEntry,
    PackageNotFound,
    _EXCLUDE,
    _INCLUDE,
    _find_packages,
    _resolve_dependencies,
    )


@pytest.fixture(scope='function')
def pkg_bash_i386():
    files = [
        flexmock(path='/tmp/pkg-bash/bin/bash',
                 chroot_path='/bin/bash',
                 dirname='/bin',
                 basename='bash',
                 file_type=PathEntry.EXECUTABLE,
                 package=pkg_bash_amd64,
                 dep_lib_names=set(['ld-linux-x86-64.so.2']))
    ]

    versions = [
        flexmock(version='3.4')
    ]

    return flexmock(
        name='bash',
        fullname='bash:i386',
        architecture='i386',
        versions=versions,
        candidate=flexmock(version='3.4'),
        all_files=files)

@pytest.fixture(scope='function')
def pkg_bash_amd64():
    versions = [
        flexmock(version='3.4')
    ]

    return flexmock(
        name='bash',
        fullname='bash:amd64',
        architecture=lambda:'amd64',
        versions=versions,
        candidate=flexmock(version='3.4'))

@pytest.fixture(scope='function')
def pkg_libc():
    return flexmock()

@pytest.fixture(scope='function')
def apt_cache_mock(pkg_bash_i386, pkg_bash_amd64):
    packages = {
        'bash': pkg_bash_amd64,
        'bash:i386': pkg_bash_i386,
        'bash:amd64': pkg_bash_amd64}
    return packages

@pytest.fixture(scope='function')
def file_system(pkg_bash_amd64, pkg_libc):
    path_entries = [
        flexmock(path='/tmp/pkg-bash/bin/bash',
                 chroot_path='/bin/bash',
                 dirname='/bin',
                 basename='bash',
                 file_type=PathEntry.EXECUTABLE,
                 package=pkg_bash_amd64,
                 dep_lib_names=set(['ld-linux-x86-64.so.2'])),
        flexmock(path='/tmp/pkg-libc/lib64/ld-linux-x86-64.so.2',
                 chroot_path='/lib64/ld-linux-x86-64.so.2',
                 dirname='/lib64',
                 basename='ld-linux-x86-64.so.2',
                 package=pkg_libc,
                 file_type=PathEntry.LINK,
                 dep_lib_names=None),
        flexmock(path='/tmp/pkg-libc/lib/x86_64-linux-gnu/ld-2.21.so',
                 chroot_path='/lib/x86_64-linux-gnu/ld-2.21.so',
                 dirname='/lib',
                 basename='ld-2.21.so',
                 package=pkg_libc,
                 file_type=PathEntry.SHARED_LIB,
                 dep_lib_names=None),
        ]

    return FileSystem(path_entries)


@pytest.mark.parametrize('patterns, value, expect', [
    (['/ab/*'],      '/ab/cd', _INCLUDE),
    (['/ab'],        '/ab/cd', None),
    (['-/ab/*'],     '/ab/cd', _EXCLUDE),
    (['/ab', '/cd'], '/de',    None),
])
def test_pattern_list(patterns, value, expect):
    pl = PatternList(map(Pattern, patterns))
    assert pl.match(value) == expect


@pytest.mark.parametrize('raw, architecture, sources, packages', [
    ('''
     [global]
     architecture = i386
     sources =
         http://archive.ubuntu.com/ubuntu/ wily main restricted

     [packages]
     bash =
         /bin/bash
     zip
     zsh:i386 = no-deps
     ''',
     # expectations:
     'i386',
     ['http://archive.ubuntu.com/ubuntu/ wily main restricted'],
     [
        Package('bash', None, None, pattern=[Pattern('/bin/bash')]),
        Package('zip', None, None),
        Package('zsh', 'i386', ['no-deps'])
     ]),

    ('''
     [global]
     sources =
         http://archive.ubuntu.com/ubuntu/ wily main restricted

     [packages]
     bash =
         /bin/*
         /etc/**
     dash = ldd-deps version==0.5.7
     zip = no-deps
         /usr/bin/zip
     zsh = no-deps
     ''',
     # expectations:
     'amd64',
     ['http://archive.ubuntu.com/ubuntu/ wily main restricted'],
     [
        Package('bash', None, None,
            pattern=[Pattern('/bin/*'), Pattern('/etc/**')]),
        Package('dash', None, ['ldd-deps'], [('==', '0.5.7')]),
        Package('zip', None, ['no-deps'],
            pattern=[Pattern('/usr/bin/zip')]),
        Package('zsh', None, ['no-deps'])
     ]),
])
def test_read_config(raw, architecture, sources, packages):
    config = Config()
    config.readfp(StringIO(dedent(raw)))

    assert config.architecture == architecture
    assert config.sources      == sources
    assert config.packages     == packages


@pytest.mark.parametrize('raw_config, expected_fullnames', [
    # common case, fallback architecture
    ('''
     bash
     ''',
     ['bash:amd64']),

    # with architecture - same architecture
    ('''
     bash:amd64
     ''',
     ['bash:amd64']),

    # same package, different architecture
    ('''
     bash:i386
     bash:amd64
     ''',
     ['bash:i386', 'bash:amd64']),
])
def test_find_packages(apt_cache_mock, raw_config, expected_fullnames):
    raw_config = dedent('''
    [global]
    sources = fake-url

    [packages]
    ''') + dedent(raw_config)

    config = Config()
    config.readfp(StringIO(raw_config))

    result = _find_packages(config, apt_cache_mock)
    fullnames = [p.apt_pkg.fullname for p in result]

    assert fullnames == expected_fullnames


@pytest.mark.parametrize('raw_config', [
    'bash:arm',
    'zsh',
    'zsh:amd64',
])
def test_find_packages_not_found(apt_cache_mock, raw_config):
    raw_config = dedent('''
    [global]
    sources = fake-url

    [packages]
    ''') + dedent(raw_config)

    config = Config()
    config.readfp(StringIO(raw_config))

    with pytest.raises(PackageNotFound):
        _find_packages(config, apt_cache_mock)


def test_shared_libraries():
    output = dedent('''

        Dynamic section at offset 0x1c3ba0 contains 26 entries:
          Tag        Type                         Name/Value
         0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
         0x000000000000000e (SONAME)             Library soname: [libc.so.6]
         0x000000000000000c (INIT)               0x207a0
         0x0000000000000019 (INIT_ARRAY)         0x3c0640
         0x000000000000001b (INIT_ARRAYSZ)       16 (bytes)
         0x0000000000000004 (HASH)               0x1bc9b8
         0x000000006ffffef5 (GNU_HASH)           0x2b8
         0x0000000000000005 (STRTAB)             0x10dc8
         0x0000000000000006 (SYMTAB)             0x3d30
         0x000000000000000a (STRSZ)              22779 (bytes)
         0x000000000000000b (SYMENT)             24 (bytes)
         0x0000000000000003 (PLTGOT)             0x3c4000
         0x0000000000000002 (PLTRELSZ)           288 (bytes)
         0x0000000000000014 (PLTREL)             RELA
         0x0000000000000017 (JMPREL)             0x1f2f8
         0x0000000000000007 (RELA)               0x17b88
         0x0000000000000008 (RELASZ)             30576 (bytes)
         0x0000000000000009 (RELAENT)            24 (bytes)
         0x000000006ffffffc (VERDEF)             0x17828
         0x000000006ffffffd (VERDEFNUM)          23
         0x000000000000001e (FLAGS)              STATIC_TLS
         0x000000006ffffffe (VERNEED)            0x17b58
         0x000000006fffffff (VERNEEDNUM)         1
         0x000000006ffffff0 (VERSYM)             0x166c4
         0x000000006ffffff9 (RELACOUNT)          1189
         0x0000000000000000 (NULL)               0x0
    ''')

    flexmock(PathEntry, _file_type=PathEntry.EXECUTABLE)
    flexmock(subprocess).should_receive('check_output') \
        .and_return(output)

    result = PathEntry('/tmp/pkg/bin/bash', '/bin/bash', flexmock())

    assert result.dep_lib_names == set(['ld-linux-x86-64.so.2'])
    assert result.soname == set(['libc.so.6'])


def test_file_system(file_system):
    flexmock(os).should_receive('readlink') \
        .with_args('/tmp/pkg-libc/lib64/ld-linux-x86-64.so.2') \
        .and_return('/lib/x86_64-linux-gnu/ld-2.21.so')

    path_entries = file_system.find_by_basename(
        'ld-linux-x86-64.so.2', [PathEntry.SHARED_LIB, PathEntry.LINK])

    assert len(path_entries) == 1
    path_entry = path_entries[0]

    dests = file_system.follow_link(path_entry)

    assert len(dests) == 1
    dest = dests[0]
    assert dest.chroot_path == '/lib/x86_64-linux-gnu/ld-2.21.so'


#def test_resolve_dependencies(pkg_bash_amd64, pkg_libc):
#    _resolve_dependencies([pkg_bash_amd64, pkg_libc])

