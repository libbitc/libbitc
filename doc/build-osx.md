Building `libbitc` on OS X
===========================

Instructions by @[colindean](http://github.com/colindean).



Dependencies
------------

This guide assumes usage of [Homebrew](http://brew.sh) or
[MacPorts](https://www.macports.org) for installing dependencies.

You will need to install `GMP` in order to build *libbitc*, plus `libevent`
and `jansson` to build *bitsy*.

Install these packages. It will take a few minutes.

    brew install autoconf automake libtool argp-standalone jansson libevent gmp

or

    sudo port install autoconf automake libtool argp-standalone jansson libevent pkgconfig gmp


Building
--------

Homebrew

    ./autogen.sh
    ./configure
    make

MacPorts

    ./autogen.sh
    ./configure CPPFLAGS="-I /opt/local/include -L /opt/local/lib"
    make


You should also run `make check` in order to run tests. This is a vital step
early in the development of `libbitc`.

You can install it if you want with `make install`. It will be installed to 
`/usr/local/libbitc`.

The `bitsy` binary will be in `./src`.

Running
-------

To ensure that at least the basics compiled correctly, execute a command:

    src/bitsy list-settings

You should see output formatted in JSON,

    {
      "wallet": "bitsy.wallet",
      "chain": "bitcoin",
      "net.connect.timeout": "11",
      "peers": "bitsy.peers",
      "blkdb": "bitsy.blkdb"
    }

If that works, `bitsy` is ready for use.
