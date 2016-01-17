Bootstraps a Debian system into a target directory with minimal dependencies
for minimal root file system size. It let you choose which files of a debian
package should be in your target root file system.

Debrootstrap generates a minimalistic root system for a single executable
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
        http://archive.ubuntu.com/ubuntu/ wily universe

    [packages]
    redis-server = ldd-deps version>=2:3.0.3-3
        /usr/bin/redis-server    # include a binary

## Getting started

Checkout from github

    git clone https://github.com/peick/debrootstrap.git
    
Running it

    cd debrootstrap
    python debrootstrap.py -h
