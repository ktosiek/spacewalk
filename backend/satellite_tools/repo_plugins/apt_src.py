import gzip
import os
import re
import sys
import urllib
import urlparse
from StringIO import StringIO

import requests

from spacewalk.common import fileutils, rhnLog, rhn_pkg
from spacewalk.common.rhnException import rhnFault
from spacewalk.satellite_tools.reposync import ContentPackage


CACHE_DIR = '/var/cache/rhn/reposync/apt/'


class AptURLException(Exception):
    """Error when parsing URL"""


def exit_on_error(f):
    """decorator for crashing on exceptions"""
    def wrapped(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception:
            import traceback; traceback.print_exc()
            sys.exit(1)

    return wrapped


class ContentSource(object):
    def __init__(self, url, name):
        url_parts = urlparse.urlparse(url)
        query = urlparse.parse_qs(url_parts.query)
        try:
            distro, = query.pop('distro')
        except (KeyError, ValueError):
            raise AptURLException(
                "There should be one 'distro' in the URL {0}".format(url))

        try:
            component, = query.pop('component', ('main', ))
        except (KeyError, ValueError):
            raise AptURLException(
                "There should be at most one 'component' in the URL {0}"
                .format(url))

        try:
            arch, = query.pop('arch')
        except KeyError:
            raise AptURLException(
                "There should be one 'arch' in the URL {0}"
                .format(url))

        new_query_str = urllib.urlencode(query, doseq=True)
        repo_url = urlparse.urlunparse(url_parts._replace(query=new_query_str))

        self.repo_url = repo_url
        self.distro = distro
        self.component = component
        self.arch = arch
        self.channel_name = name

    def clear_ssl_cache(self):
        pass

    @exit_on_error
    def list_packages(self, filters):
        """Download and list the packages in repo"""
        if filters:
            raise NotImplemented('filters are not implemented')
        self.num_excluded = 0  # Filters are not implemented
        all_packages = []
        for packages_file in self._get_packages_files():
            packages_iter = parse_packages(packages_file)
            for package in packages_iter:
                epoch, version, release = split_version(package['Version'])
                new_pack = DebianPackage()
                new_pack.setNVREA(
                    name=package['Package'],
                    epoch=epoch, version=version, release=release,
                    arch=deb_to_spacewalk_arch(package['Architecture']))
                new_pack.package_filename = package['Filename']
                new_pack.checksum, new_pack.checksum_type = \
                    preferred_checksum(package)

                # TODO: only for debugging, eats memory like candy
                new_pack._pack_dict = package

                all_packages.append(new_pack)
        self.num_packages = len(all_packages)
        return all_packages

    @exit_on_error
    def get_package(self, pack):
        filename = pack.package_filename
        package_url = "{self.repo_url}/{filename}".format(**locals())
        download_path = "{base}/{filename}".format(
            base=CACHE_DIR,
            filename=filename)

        r = requests.get(package_url, stream=True)
        assert r.status_code == 200

        download_dir = os.path.dirname(download_path)
        if not os.path.isdir(download_dir):
            os.makedirs(download_dir)

        with open(download_path, 'wb') as f:
            for chunk in r.iter_content():
                f.write(chunk)

        return download_path

    def get_groups(self):
        # TODO: what is this thing?
        pass

    def get_updates(self):
        # TODO: get package Errata - that is, summary of changes
        return []

    def _get_packages_files(self):
        """Get the Packages files for all archs."""
        for url in self._get_packages_urls():
            yield self._get_url(url)

    def _get_url(self, url):
        """Returns a file-like for `url`.gz or `url`"""
        response = requests.get(url + '.gz')
        if response.status_code == 404:
            response = requests.get(url)
            return StringIO(response.content)
        return gzip.GzipFile(fileobj=StringIO(response.content), mode='rb')

    def _get_packages_urls(self):
        for arch in (self.arch, ):  # 'all'): is the 'all' needed for Debian?
            yield ("{s.repo_url}/dists/{s.distro}/{s.component}/"
                   "binary-{arch}/Packages").format(s=self, arch=arch)


version_regex = re.compile(r"""
    (?:(?P<epoch>\d+):)?  # The epoch
    (?P<version>\d[^-]*)  # Version, starts with a digit and ends before a -
    (?:-(?P<release>[^-]+))?  # Release, everything after -
    """, re.VERBOSE)


def split_version(version):
    """Returns (epoch, version, release), where epoch and release might be None
    """
    match = re.match(version_regex, version)
    if match is None:
        raise ValueError('Wrong version string {0}'.format(version))
    return match.groups()


def parse_packages(packages_file):
    """yield a dictionary for each entry in packages_file"""
    package = {}
    field = {'name': None, 'lines': []}
    field_name = None
    field_lines = []

    def add_field():
        if field['name'] is None:
            return

        if field['name'] in package:
            raise ValueError('malformed Packages file!')
        package[field['name']] = '\n'.join(field['lines'])
        field['name'] = None
        field['lines'] = []

    for line in packages_file:
        if line.startswith('#'):
            # Comments
            continue

        if line.endswith('\n'):
            line = line[:-1]

        # End of package
        if not line.strip():
            if package:
                add_field()
                yield package
                package = {}
        else:
            # next line of package
            # if it starts with whitespace, it's a continuation
            if line.startswith(' ') or line.startswith('\t'):
                assert field_name is not None
                field_lines.append(line)
            else:
                add_field()
                field['name'], first_line = line.split(':', 1)
                field['lines'].append(first_line.strip())

    add_field()
    if package:
        yield package


def preferred_checksum(package_dict):
    """Get the preferred checksum and it's name from package_dict"""
    # starts with MD5, as that's what DEB_Package.payload_checksum() will show
    checksums = ('MD5sum', 'md5'), ('SHA256', 'sha256'), ('SHA1', 'sha1')
    for field, name in checksums:
        if field in package_dict:
            return package_dict[field], name


def deb_to_spacewalk_arch(arch):
    if not arch.endswith('-deb'):
        return arch + '-deb'
    return arch


class DebianPackage(ContentPackage):
    def load_checksum_from_header(self):
        if self.path is None:
            raise rhnFault(50, "Unable to load package", explain=0)
        self.file = open(self.path, 'rb')
        self.a_pkg = rhn_pkg.package_from_stream(self.file, packaging='deb')
        self.a_pkg.read_header()
        self.a_pkg.payload_checksum()
        self.file.close()

    def setNVREA(self, name, version, release, epoch, arch):
        """Set NVREA with default release and epoch"""
        ContentPackage.setNVREA(
            self, name, version, release or '0', epoch or '', arch)

    def getNVREA(self):
        return ''.join((
            self.name,
            '-', self.version,
            '-' + self.release,
            ('-' + self.epoch if self.epoch else ''),
            '.', self.arch))
