# libbitc

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/libbitc/libbitc/master/COPYING) <a href="https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki"><img src="https://upload.wikimedia.org/wikipedia/commons/6/6b/Segwit.svg" alt="Segregated Witness" width="9%" height="9%"/></a>

[![Build Status](https://travis-ci.org/libbitc/libbitc.svg?branch=master)](https://travis-ci.org/libbitc/libbitc) [![Coverage Status](https://coveralls.io/repos/github/libbitc/libbitc/badge.svg?branch=master)](https://coveralls.io/github/libbitc/libbitc?branch=master) [![Coverity Scan Build Status](https://scan.coverity.com/projects/8959/badge.svg)](https://scan.coverity.com/projects/libbitc-libbitc)

[![Join the chat at https://gitter.im/libbitc/libbitc](https://badges.gitter.im/libbitc/libbitc.svg)](https://gitter.im/libbitc/libbitc?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![Join the chat at https://irc.gitter.im/#libbitc](https://img.shields.io/badge/chat-on%20irc-green.svg)](https://irc.gitter.im/) [![Join the chat at https://libbitc.slack.com](https://img.shields.io/badge/chat-on%20slack-yellowgreen.svg)](https://libbitc.slack.com)

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/libbitc/libbitc)

An itsy-bitsy bitcoin library, with lightweight client and utils.

This contains several pieces of interest:
* **libbitc** - C library for building bitcoin applications
* **bitsy** - (WIP) Bitcoin HD wallet
* **brd** - (WIP) Bitcoin network full node ("block relay daemon")
* Comprehensive test suite.

libbitc library dependencies:
	GMP

bitsy client dependencies:
	GMP

block relay daemon (brd) dependencies:
	GMP



Command line and configuration file usage
=========================================

The bitsy wallet is operated via command line, in a similar
style to "git sub-command".  To obtain a list of commands, run

	$ ./bitsy --help

The program stores settings in a key/value map.  These key=value
parameters may be specified on the command line via --set, or in a
configuration file.  To view these settings, run

	$ ./bitsy settings




Recognized parameters
=====================

addnode
------------------
Format: address SPACE port

Manually add P2P node to peer manager.


config (alias "c")
------------------
Specify a pathname to the configuration file.


wallet (alias "w")
------------------
Specify a pathname to the wallet data file.  Default "bitsy.wallet"

AES encryption is applied to the wallet.  Passphrase is specified via
environment variable BITSY_PASSPHRASE.


debug
------------------
Enable additional debug output.

net.connect.timeout
------------------
TCP connect(2) timeout.


Recognized commands
===================

chain-set
---------
Select blockchain and network.  Reads the "chain" settings variable.
Acceptable values are "chain=bitcoin" and "chain=testnet3".  Updates
internal parameters (pchMessageStart / network magic, genesis block, ...)

dns-seeds
---------
Query and display bitcoin DNS seeds, for P2P node addresses.

settings
--------
Display settings map.

address
-------
Generate a new bitcoin address (ECDSA keypair).  Store it in the current
wallet,

create
------
Initialize a new wallet.  Refuses to initialize, if the filename already
exists.

createAccount
-------------
Create new HD account.

netsync
-------
Synchronize with network: send any pending payments, and check for
new incoming payments.

addressList
-----------
List all legacy non-HD bitcoin addresses in wallet.

dump
----
Dump entire wallet contents, including all private keys.

info
----
Informational summary of wallet data.

