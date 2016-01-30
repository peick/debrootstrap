#!/usr/bin/env python
'''Bootstrap a Debian system into a target directory with minimal dependencies
for minimal root file system size. Let's you choose which files of a debian
package should be in your target root file system.

%prog is ideal to generate a minimalistic root system for a single executable
with all its dependent shared library, but not more. No docs, no configuration,
no localization - unless you explicitly want them.

It is inspired by debootstrap, but not a replacement, because it does not
configure the packages. It just extracts the content from the configured debian
packages.

Configuration example:

    [global]
    # optional. Defaults to amd64
    architecture = amd64

    # optional. Defaults to /etc/apt/trusted.gpg
    keyring = /etc/apt/trusted.gpg

    # list of apt sources as seen in /etc/apt/sources.list without 'deb' prefix
    sources =
        http://archive.ubuntu.com/ubuntu/ wily main restricted
        http://archive.ubuntu.com/ubuntu/ wily-updates main restricted
        http://archive.ubuntu.com/ubuntu/ wily multiverse
        http://archive.ubuntu.com/ubuntu/ wily universe

    [packages]
    redis-server = ldd-deps version>=2:3.0.3-3 version<=4
        /usr/bin/redis-server    # include a binary
    libc = ldd-deps
        /lib64/ld-linux-x86-64.so.2

'''
import fnmatch
import logging
import optparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib
from ConfigParser import SafeConfigParser
from collections import defaultdict

import apt
import apt_pkg
import magic


__version_info__ = (0, 1)
__version__ = '0.1'

_log = logging.getLogger(__name__)


class ConfigFormatter(optparse.IndentedHelpFormatter):
    def format_description(self, description):
        return description or ''


def _get_cli_args():
    parser = optparse.OptionParser(version='%%prog %s' % __version__,
                                   usage='%prog [options] <target>',
                                   description=__doc__,
                                   formatter=ConfigFormatter())

    parser.add_option('-v', '--verbose',
                      dest='verbose',
                      action='count',
                      default=0,
                      help='Verbose output. Shows debug informations.')
    parser.add_option('-q', '--quiet',
                      dest='quiet',
                      action='store_true',
                      help='Less verbose output. Shows only warnings and errors.')
    parser.add_option('-c', '--config',
                      dest='config',
                      help='Configuration file. Required')
    parser.add_option('--tmp-dir',
                      dest='temp_dir',
                      default=None,
                      help='Temporary working directory. Defaults to a ' \
                           'temporaray directory in the current working ' \
                           'directory')
    parser.add_option('-k', '--keep-tmp-dir',
                      dest='keep_temp_dir',
                      action='store_true',
                      help='Do not delete --tmp-dir.')

    options, args = parser.parse_args()
    options.target = None

    if args:
        options.target = os.path.abspath(args.pop(0))

    if not options.target:
        parser.error('You need to specify a target')

    if not options.config:
        parser.error('You need to specify a configuration file with -c <file>')

    return options

# ------------------------------------------------------------------------

class DebrootstrapError(Exception):
    pass

class ConfigError(Exception):
    pass

class PackageNotFound(Exception):
    pass

class PathEntryError(Exception):
    pass

# ------------------------------------------------------------------------

_INCLUDE = 'INCLUDE'
_EXCLUDE = 'EXCLUDE'

_remove_comment = lambda s: re.sub(r'\s+#.*$', '', s).strip()

# ------------------------------------------------------------------------

class ConfigParser(SafeConfigParser):
    # allows options with a ':' in name
    OPTCRE_NV = re.compile(
        r'(?P<option>[^=\s][^=]*)'
        r'\s*(?:'
        r'(?P<vi>[=])\s*'
        r'(?P<value>.*))?$')


class Config(object):
    def __init__(self):
        self.packages = []
        self.architecture = None
        self.sources = []
        self.keyring = None
        self.keyring_dir = None


    def readfp(self, file_obj):
        config = ConfigParser(allow_no_value=True)
        config.readfp(file_obj)

        self.architecture = self._read_global(config, 'architecture', 'amd64')

        self.keyring = self._read_global(config, 'keyring', '/etc/apt/trusted.gpg')
        self.keyring_dir = self._read_global(config, 'keyring_dir', '/etc/apt/trusted.gpg.d')

        post_build = self._read_global(config, 'post-build', '')
        self.post_build = _load_scripts(post_build)

        sources = self._read_global(config, 'sources', '').strip()
        if not sources:
            raise ConfigError('missing sources in [global]')
        self.sources = map(_remove_comment, sources.splitlines())

        self.packages = self._read_packages(config)
        assert self.architecture


    def _read_global(self, config, key, default=None):
        if not config.has_section('global'):
            return default

        if not config.has_option('global', key):
            return default

        return config.get('global', key)


    def _parse_flags(self, line, package_name):
        pattern = r'''
            (?:
                (?P<version>version\s*(?P<cmp>>=|<=|==|>|<)\s*(?P<v>\S+))
                |
                (?P<constant>ldd-deps|no-deps|deps)
                |
                (?P<unknown>\S+)
                (?:\s+|$)
            )
            '''

        flags = []
        version_cmp = []

        for match in re.finditer(pattern, line, re.VERBOSE):
            if match.group('version'):
                comp = match.group('cmp')
                version = match.group('v')
                version_cmp.append((comp, version))
            elif match.group('constant'):
                flags.append(match.group('constant'))
            elif match.group('unknown'):
                raise ConfigError('unknown flag %r for package %s' \
                                  % (match.group('unknown'), package_name))
        return flags, version_cmp


    def _read_packages(self, config):
        if not config.has_section('packages'):
            return []

        packages = []
        for option in config.options('packages'):
            value = config.get('packages', option)
            if not value:
                value = ''
            lines = value.splitlines()

            if lines:
                flags, version_cmp = self._parse_flags(
                    _remove_comment(lines[0]), option)
            else:
                flags, version_cmp = [], []

            if ':' in option:
                option, architecture = option.split(':', 1)
            else:
                architecture = None

            package = Package(option, architecture, flags, version_cmp or None)

            for line in lines[1:]:
                p = Pattern(_remove_comment(line))
                package.add_pattern(p)

            packages.append(package)

        return packages

# ------------------------------------------------------------------------

class Script(object):
    def __init__(self, command):
        self._commands = [command]

    def __call__(self, target):
        assert target.startswith('/') and len(target) > 2

        for cmd in self._commands:
            _log.debug('running command: %s', cmd)
            subprocess.check_call(
                cmd, shell=True, env={'TARGET': target})


class ScriptFunction(Script):
    parser_options = []

    def __init__(self, raw):
        options, args = self._parse_options(raw.split())
        self._commands = self._generate_commands(options, args)

    def _parse_options(self, unparsed_args):
        parser = optparse.OptionParser(option_list=self.parser_options)
        options, args = parser.parse_args(unparsed_args)
        return options, args

    def _generate_commands(self, options, args):
        raise NotImplementedError()


class ScriptFunctionUPX(ScriptFunction):
    parser_options = [optparse.Option('--all', action='store_true')]

    def _generate_commands(self, options, args):
        if not args:
            raise ConfigError('${upx} function needs arguments')

        args = ['$TARGET/%s' % arg for arg in args]

        cmd = "find %s -type f " % ' '.join(args)
        if not options.all:
            cmd += "-exec file --mime-type {} \; " \
                   "| grep ':\s*application/\(x-executable\|x-sharedlib\)' " \
                   "| cut -d':' -f1"
        cmd += "| /usr/bin/xargs --no-run-if-empty upx --best --ultra-brute"
        return [cmd]


class ScriptFunctionInstallBusybox(ScriptFunction):
    def _generate_commands(self, options, args):
        if args:
            raise ConfigError('${busybox} function does not take any arguments')

        return ["$TARGET/bin/busybox --list-full " \
                    "| /usr/bin/xargs -n1 dirname " \
                    "| sort " \
                    "| uniq " \
                    "| /usr/bin/xargs -n1 -I '{}' mkdir -p $TARGET/'{}'",
                "$TARGET/bin/busybox --list-full " \
                    "| /usr/bin/xargs -n1 -I '{}' sh -c \"test -e $TARGET/'{}' || ln -s /bin/busybox $TARGET/'{}'\""]


_script_functions = {
    'upx':             ScriptFunctionUPX,
    'install_busybox': ScriptFunctionInstallBusybox,
}


def _load_scripts(raw):
    function_re = re.compile(r'\$\{(\S+)(?:\s+(.*))?\}$')

    scripts = []
    for command in raw.splitlines():
        command = command.strip()
        if not command:
            continue

        match = function_re.match(command)
        if match:
            name = match.group(1)
            raw_args = match.group(2)
            if name not in _script_functions:
                raise ConfigError('script function %r not found')

            if not raw_args:
                raw_args = ''

            script = _script_functions[name](raw_args.strip())
        else:
            script = Script(command)
        scripts.append(script)

    return scripts

# ------------------------------------------------------------------------

class Pattern(object):
    def __init__(self, pattern):
        if pattern.startswith('-'):
            self._exclude = True
            self._pattern = pattern[1:]
        else:
            self._exclude = False
            self._pattern = pattern


    def __eq__(self, other):
        return self.__dict__ == other.__dict__


    def __repr__(self):
        exclude = '-' if self._exclude else ''
        return '<Pattern %s%s>' % (exclude, self._pattern)


    def match(self, value):
        if fnmatch.fnmatch(value, self._pattern):
            if self._exclude:
                return _EXCLUDE
            else:
                return _INCLUDE


class PatternList(list):
    def match(self, value):
        for pattern in self:
            match = pattern.match(value)
            if match:
                return match


class Package(object):
    def __init__(self, name, architecture, flags, version_cmp=None, pattern=None):
        self.name = name
        self.architecture = architecture
        self.flags = flags or None
        self._version_cmp = version_cmp
        self._patterns = PatternList()

        # set by _find_packages
        self.apt_pkg = None

        # list of all files (PathEntry) in a .deb package. Set by _extract_packages
        self.all_files = None

        if pattern:
            self._patterns.extend(pattern)


    def __eq__(self, other):
        return self.__dict__ == other.__dict__


    def __repr__(self):
        if self.flags:
            flags = ','.join(map(repr, self.flags))
        else:
            flags = None
        return '<Package name: %r architecture: %r, flags: %s>' % (
                self.name, self.architecture, flags)


    def __getitem__(self, key):
        for path_entry in self.included_files():
            if path_entry.basename == key:
                return path_entry
        raise KeyError()


    @property
    def hard_deps(self):
        if self.flags:
            return 'no-deps' not in self.flags and 'ldd-deps' not in self.flags
        return True


    @property
    def soft_deps(self):
        return 'ldd-deps' in self.flags if self.flags else False


    def add_pattern(self, pattern):
        self._patterns.append(pattern)


    def _default_pattern(self):
        if self._patterns:
            return Pattern('-**/*')
        elif self.hard_deps:
            return Pattern('**/*')
        else:
            return Pattern('-**/*')


    def is_excluded(self, path_entry):
        match = self._patterns.match(path_entry.chroot_path)
        if match and match == _EXCLUDE:
            return True


    def included_files(self):
        if not self.all_files:
            return []

        files = []

        default_pattern = self._default_pattern()

        for path_entry in self.all_files:
            match = self._patterns.match(path_entry.chroot_path) or \
                    default_pattern.match(path_entry.chroot_path)

            if match and match == _INCLUDE:
                files.append(path_entry)

        return files


    def dep_lib_names(self):
        libs = set()

        if not self.hard_deps and not self.soft_deps:
            return libs

        for path_entry in self.included_files():
            if path_entry.file_type in (PathEntry.EXECUTABLE,
                                        PathEntry.SHARED_LIB):
                if path_entry.dep_lib_names:
                    libs.update(path_entry.dep_lib_names)
        return libs


    def version_filter(self, version):
        if not self._version_cmp:
            return True

        for comparator, value in self._version_cmp:
            if comparator == '<' and not version < value or \
                comparator == '<=' and not version <= value or \
                comparator == '==' and not version == value or \
                comparator == '>=' and not version >= value or \
                comparator == '>'  and not version > value:
                return False
        return True


class PathEntry(object):
    DIRECTORY       = 'DIR'
    LINK            = 'LNK'
    EXECUTABLE      = 'EXE'
    FILE            = 'FIL'
    SHARED_LIB      = 'SHA'
    LINK_SHARED_LIB = 'LSH'

    def __init__(self, path, chroot_path, package):
        self.path        = path
        self.chroot_path = chroot_path
        self.dirname     = os.path.dirname(chroot_path)
        self.basename    = os.path.basename(path)
        self.package     = package

        self.file_type = self._file_type(path)

        if self.file_type in (PathEntry.EXECUTABLE, PathEntry.SHARED_LIB):
            dep_lib_names, soname = self._shared_libraries(path)
        else:
            dep_lib_names, soname = None, None
        self.dep_lib_names = dep_lib_names
        self.soname = soname


    def __repr__(self):
        return '<PathEntry %s: %r>' % (self.file_type, self.chroot_path)


    def _file_type(self, path):
        if os.path.islink(path):
            return PathEntry.LINK

        if os.path.isdir(path):
            return PathEntry.DIRECTORY

        m = magic.open(magic.MAGIC_MIME_TYPE)
        m.load()
        path = path.decode('utf-8')
        mimetype = m.file(path)
        m.close()

        mapping = {
            'application/x-executable': PathEntry.EXECUTABLE,
            'application/x-sharedlib':  PathEntry.SHARED_LIB}
        return mapping.get(mimetype, PathEntry.FILE)


    def _shared_libraries(self, path):
        """Return a set of shared libraries base names for an elf binary.
        """
        pattern = r'(?:(Shared library)|(Library soname)):\s*\[([^\]]+)\]'
        cmd = ['readelf', '-d', path]
        env = {'LANG': 'C'}
        libs = set()
        soname = set()
        output = subprocess.check_output(cmd, env=env)
        for line in output.splitlines():
            match = re.search(pattern, line)
            if match:
                name = match.group(3)
                if match.group(1):
                    libs.add(name)
                else:
                    assert match.group(2)
                    soname.add(name)
        return libs, soname

# ------------------------------------------------------------------------

class FileSystem(object):
    def __init__(self, path_entries):
        index = {}
        basename_index = defaultdict(list)

        for path_entry in path_entries:
            if path_entry.file_type == PathEntry.DIRECTORY:
                continue

            path = path_entry.chroot_path

            if path in index:
                old_path_entry = index[path_entry.chroot_path]
                _log.warn('file %s from package %s overridden by package %s',
                      path, old_path_entry.package.name, path_entry.package.name)

            index[path] = path_entry
            basename_index[path_entry.basename].append(path_entry)

        self._index = index
        self._basename_index = dict(basename_index)


    def follow_link(self, path_entry):
        """Follows the link `path_entry` and return a list of PathEntry objects
        to the destination.

        Raises a KeyError if the entry was not found.
        """
        if path_entry.file_type != PathEntry.LINK:
            raise PathEntryError('%s is not a link' % path_entry.path)

        found = []
        while path_entry.file_type == PathEntry.LINK:
            dest = os.readlink(path_entry.path)
            dest_abs = os.path.abspath(os.path.join(path_entry.dirname, dest))

            path_entry = self[dest_abs]
            found.append(path_entry)
        return found


    def find_by_basename(self, basename, file_types):
        """Return a list of path entries of a given file type that match the
        file's basename.
        """
        path_entries = self._basename_index.get(basename, [])
        return [p for p in path_entries if p.file_type in file_types]


    def __getitem__(self, path):
        assert isinstance(path, (bytes, str))
        return self._index[path]

# ------------------------------------------------------------------------

def _init_admin_rootfs(config, options, base):
    _log.info('set root directory to %s', base)
    required_dirs = [
        os.path.join(base, 'etc', 'apt', 'trusted.gpg.d'),
        os.path.join(base, 'var', 'cache', 'apt', 'archives', 'partial'),
        os.path.join(base, 'var', 'lib', 'apt', 'lists', 'partial'),
        os.path.join(base, 'var', 'lib', 'dpkg', 'updates'),
        os.path.join(base, 'var', 'lib', 'dpkg', 'info'),
        os.path.join(base, 'var', 'lib', 'dpkg', 'triggers'),
        os.path.join(base, 'var', 'log', 'apt'),
        os.path.join(base, 'tmp'),
        ]
    for d in required_dirs:
        if not os.path.exists(d):
            _log.debug('creating %s', d)
            os.makedirs(d)

    open(os.path.join(base, 'status'), 'a').write('')

    key_available = False

    if os.path.exists(config.keyring):
        dest = os.path.join(base, 'etc', 'apt', 'trusted.gpg')
        shutil.copy2(config.keyring, dest)
        key_available = True

    dest = os.path.join(base, 'etc', 'apt', 'trusted.gpg.d')
    if os.path.exists(config.keyring_dir):
        for cur_dir, dirs, files in os.walk(config.keyring_dir):
            for f in files:
                src = os.path.join(config.keyring_dir, cur_dir, f)
                shutil.copy2(src, dest)
                key_available = True

    if not key_available:
        raise ConfigError('No keyring installed in %s' % dest)


def _check_target(options):
    if os.path.exists(options.target):
        raise DebrootstrapError('Target %s already exists.' % options.target)


def _write_sources_list(config, options, base):
    path = os.path.join(base, 'etc', 'apt', 'sources.list')
    _log.debug('generating %s', path)

    deb_sources = ['deb %s' % s for s in config.sources]
    sources = '\n'.join(deb_sources)
    open(path, 'w').write(sources)


def _find_packages(config, cache):
    not_found = []

    for package in config.packages:
        if package.architecture:
            query = '%s:%s' % (package.name, package.architecture)
        else:
            query = package.name

        try:
            pkg = cache[query]
        except KeyError:
            not_found.append(query)
            continue

        # select version
        candidates = [version for version in pkg.versions
                      if package.version_filter(version)]
        if not candidates:
            vx = [v.version for v in pkg.versions]
            raise PackageNotFound(
                    'the package %s was not found in the desired version.' \
                    ' Available versions: %s' \
                    % (pkg.fullname, ', '.join(vx)))

        if len(candidates) > 2:
            vx = [v.version for v in candidates]
            raise PackageNotFound(
                    'the package %s is available in multiple versions: %s ' \
                    % (pkg.fullname, ', '.join(vx)))

        pkg.candidate = candidates[0]

        package.apt_pkg = pkg
        _log.info('found package %s %s', pkg.fullname, pkg.candidate.version)

    for query in sorted(not_found):
        _log.error('the package %s was not found.', query)

    if not_found:
        raise PackageNotFound('Some packages were not found.')

    return config.packages


def _find_dependent_packages(cache, packages):
    install_pkgs = [p.apt_pkg for p in packages]
    dep_pkgs     = []
    lib_dep_pkgs = []

    # hard dependencies
    for package in packages:
        if package.hard_deps:
            package.apt_pkg.mark_install(auto_fix=False, auto_inst=False)
            package.apt_pkg.mark_install(auto_fix=False, auto_inst=True)

    for pkg in cache.get_changes():
        if pkg not in install_pkgs:
            dep_pkgs.append(pkg)
            _log.info('dependency package %s %s', pkg.fullname, pkg.candidate.version)

    # dependencies to library packages (lib-deps)
    for package in packages:
        if package.soft_deps:
            package.apt_pkg.mark_install(auto_fix=False, auto_inst=False)
            package.apt_pkg.mark_install(auto_fix=False, auto_inst=True)

    for pkg in cache.get_changes():
        if pkg not in install_pkgs and pkg not in dep_pkgs:
            lib_dep_pkgs.append(pkg)
            _log.info('library dependency package %s %s', pkg.fullname, pkg.candidate.version)

    # packages without dependencies
    for package in packages:
        if not package.hard_deps and not package.soft_deps:
            package.apt_pkg.mark_install(auto_fix=False, auto_inst=False)

    for pkg in dep_pkgs:
        package = Package(pkg.name, pkg.architecture(), ['deps'])
        package.apt_pkg = pkg
        packages.append(package)

    for pkg in lib_dep_pkgs:
        package = Package(pkg.name, pkg.architecture(), ['ldd-deps'])
        package.apt_pkg = pkg
        packages.append(package)

    if cache.broken_count:
        _log.warn('Dependency packages not found. The result may be incorrect.')


def _scan_files(root_dir, package):
    result = []
    for cur_dir, dirs, files in os.walk(root_dir):
        cur_rel_dir = os.path.relpath(cur_dir, root_dir)

        for d in dirs:
            chroot_path = os.path.abspath(os.path.join('/', cur_rel_dir, d))
            path = os.path.join(root_dir, cur_dir, d)
            result.append(PathEntry(path, chroot_path, package))

        for f in files:
            chroot_path = os.path.abspath(os.path.join('/', cur_rel_dir, f))
            path = os.path.join(root_dir, cur_dir, f)
            result.append(PathEntry(path, chroot_path, package))

    return result


def _pkg_path_quote(s):
    tolower = lambda m: m.group(0).lower()
    return re.sub(r'%[A-Fa-f0-9]{2}', tolower, urllib.quote_plus(s, '+'))


def _extract_packages(packages, admin_base, target):
    for package in packages:
        pkg = package.apt_pkg
        _log.info('extracting %s', pkg.fullname)

        basename = '%s_%s_%s.deb' % (_pkg_path_quote(pkg.name),
                                     _pkg_path_quote(pkg.candidate.version),
                                     _pkg_path_quote(pkg.candidate.architecture))

        tmp_dir = os.path.join(admin_base, 'tmp', basename)
        debfile = os.path.join(admin_base, 'var', 'cache', 'apt', 'archives',
                               basename)

        assert os.path.exists(debfile), debfile

        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)
        else:
            assert os.path.isdir(tmp_dir)

        subprocess.check_call(['dpkg', '-x', debfile, tmp_dir])
        package.extract_dir = tmp_dir
        package.all_files = _scan_files(tmp_dir, package)


def _resolve_dependencies(packages):
    """Resolves ldd-deps depedencies.

    Requires unpackages packages.
    """
    dep_lib_names = set()
    all_files = []
    for package in packages:
        dep_lib_names.update(package.dep_lib_names())
        all_files.extend(package.all_files)

    # starting from the list of minimum required dependency libraries and
    # executables. Extends package's include pattern to match the dependencies.
    fs = FileSystem(all_files)
    found = set()
    while dep_lib_names:
        basename = dep_lib_names.pop()

        if basename in found:
            continue

        path_entries = fs.find_by_basename(
            basename, [PathEntry.LINK, PathEntry.SHARED_LIB])

        path_entries = [pe for pe in path_entries
                        if not pe.package.is_excluded(pe)]

        if not path_entries:
            _log.warn('shared library %s not found', basename)
            continue

        if len(path_entries) > 1:
            candidates = ['%s:%s' % (pe.package.name, pe.chroot_path)
                          for pe in path_entries]
            _log.info('shared library %s has more than one candidate: %s. Adding all. ',
                  basename,
                  ', '.join(candidates))

        path_entries = [path_entries[0]]
        for path_entry in path_entries:
            if path_entry.file_type == PathEntry.LINK:
                path_entries.extend(fs.follow_link(path_entry))

        file_types = [path_entry.file_type for path_entry in path_entries]
        if PathEntry.SHARED_LIB not in file_types:
            raise PathEntryError('%s is not a shared library' %
                                 path_entries[-1].chroot_path)

        for path_entry in path_entries:
            path_entry.package.add_pattern(Pattern(path_entry.chroot_path))
            _log.debug('adding shared library %s', path_entry.chroot_path)
            found.add(path_entry.basename)

        dep_lib_names.update(path_entries[-1].dep_lib_names)


def _copy_rootfs_files(target, packages):
    dirs = set()
    for package in packages:
        for path_entry in package.included_files():
            if path_entry.file_type == PathEntry.DIRECTORY:
                dirname = path_entry.chroot_path
                destdir = dest = os.path.join(target, dirname.lstrip('/'))
            else:
                dirname = path_entry.dirname
                destdir = os.path.join(target, dirname.lstrip('/'))
                dest    = os.path.join(target, path_entry.chroot_path.lstrip('/'))

            if dirname not in dirs:
                if os.path.exists(destdir):
                    assert os.path.isdir(destdir)
                else:
                    # TODO set permission and owner from package
                    os.makedirs(destdir)
                dirs.add(dirname)

            if path_entry.file_type == PathEntry.DIRECTORY:
                shutil.copystat(path_entry.path, destdir)
            elif path_entry.file_type == PathEntry.LINK:
                linkto = os.readlink(path_entry.path)
                os.symlink(linkto, dest)
            else:
                shutil.copy2(path_entry.path, dest)


def _print_rootfs_files(packages):
    fmt = []
    for package in packages:
        files = set()
        for path_entry in package.all_files:
            files.add(path_entry.chroot_path)
        files = list(files)
        files.sort()
        files = ['    %s' % path for path in files]
        fmt.append('')
        fmt.append('  %s:' % package.name)
        fmt.extend(files)

    _log.log(1,
        'all files from all packages (unfiltered):%s', '\n'.join(fmt))


def _cleanup(tmp_dir):
    _log.debug('removing %s', tmp_dir)
    shutil.rmtree(tmp_dir)

# ------------------------------------------------------------------------

def main():
    options = _get_cli_args()

    if options.verbose >= 2:
        log_level = logging.NOTSET
    elif options.verbose >= 1:
        log_level = logging.DEBUG
    elif options.quiet:
        log_level = logging.WARN
    else:
        log_level = logging.INFO
    logging.basicConfig(format='%(levelname).1s: %(message)s',
        level=log_level, stream=sys.stdout)

    config = Config()
    config.readfp(open(options.config))

    base = options.temp_dir
    if not base:
        base = tempfile.mkdtemp(dir='.', prefix='tmp-debrootstrap-')
        base_exists = False
    else:
        base_exists = os.path.exists(base)
    base = os.path.abspath(base)
    _init_admin_rootfs(config, options, base)

    _check_target(options)

    if base_exists:
        _log.warn('reusing existing directory: %s', base)
    else:
        _write_sources_list(config, options, base)
        _log.info('updating packages')
        cache = apt.Cache(rootdir=base)
        cache.update()

    cache = apt.Cache(rootdir=base)

    apt_pkg.config.clear('APT::Update::Post-Invoke-Success')
    apt_pkg.config.clear('APT::Update::Post-Invoke-Success::')
    apt_pkg.config.clear('DPkg::Pre-Install-Pkgs')
    apt_pkg.config.clear('DPkg::Pre-Install-Pkgs::')
    apt_pkg.config.clear('DPkg::Post-Invoke')
    apt_pkg.config.clear('DPkg::Post-Invoke::')
    apt_pkg.config.set('Dir::Bin::dpkg', '/usr/bin/dpkg')
    apt_pkg.config.set('DPkg::Options::', '--root=%s' % (base, ))
    apt_pkg.config.set('DPkg::Options::', '--force-depends')
    apt_pkg.config.set('DPkg::Options::', '--no-triggers')
    apt_pkg.config.set('DPkg::ConfigurePending', 'false')
    apt_pkg.config.set('DPkg::NoTriggers', 'false')

    try:
        packages = _find_packages(config, cache)
        _find_dependent_packages(cache, packages)
    except PackageNotFound as error:
        _log.error(error)
        sys.exit(1)

    cache.fetch_archives()

    _extract_packages(packages, base, options.target)
    _print_rootfs_files(packages)
    _resolve_dependencies(packages)
    _copy_rootfs_files(options.target, packages)
    for post_build_fn in config.post_build:
        post_build_fn(options.target)
    if not options.keep_temp_dir:
        _cleanup(base)


if __name__ == '__main__':
    main()

