#libbitc

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/libbitc/libbitc/master/COPYING) [![Build Status](https://travis-ci.org/libbitc/libbitc.svg?branch=master)](https://travis-ci.org/libbitc/libbitc) [![Coverage Status](https://coveralls.io/repos/github/libbitc/libbitc/badge.svg?branch=master)](https://coveralls.io/github/libbitc/libbitc?branch=master) [![Coverity Scan Build Status](https://scan.coverity.com/projects/8959/badge.svg)](https://scan.coverity.com/projects/libbitc-libbitc)

[![Join the chat at https://gitter.im/libbitc/libbitc](https://badges.gitter.im/libbitc/libbitc.svg)](https://gitter.im/libbitc/libbitc?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![Join the chat at https://irc.gitter.im/#libbitc](https://img.shields.io/badge/chat-on%20irc-green.svg)](https://kiwiirc.com/client/irc.gitter.im/#libbitc) [![Join the chat at https://libbitc.slack.com](https://img.shields.io/badge/chat-on%20slack-yellowgreen.svg)](https://libbitc.slack.com)

An itsy-bitsy bitcoin library, with lightweight client and utils

libccoin library dependencies:
	OpenSSL
	GMP

picocoin client dependencies:
	OpenSSL
	GMP
	libevent 2.x
	jansson 2.x (2.1 used for development)

block relay daemon (brd) dependencies:
	OpenSSL
	GMP
	libevent 2.x



Command line and configuration file usage
=========================================

In general, the program stores settings in a key/value map.  These key=value
parameters may be specified on the command line, or in a configuration file.

The command line is processed in-order.  For example

`$ ./picocoin value=1 list-settings value=2 list-settings`

will execute the "list-settings" command twice, each with "value" setting
initialized to a different parameter.

Similarly, you may read multiple configuration files into the settings map:

`$ ./picocoin config=file1 config=file2 config=file3`


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
Specify a pathname to the wallet data file.  Default "picocoin.wallet"

AES encryption is applied to the wallet.  Passphrase is specified via
environment variable PICOCOIN_PASSPHRASE.


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

help
----
Output these commands and recognized settings.

list-settings
-------------
Display settings map.

new-address
-----------
Generate a new bitcoin address (ECDSA keypair).  Store it in the current
wallet, 

new-wallet
----------
Initialize a new wallet.  Refuses to initialize, if the filename already
exists.

netsync
-------
Synchronize with network: send any pending payments, and check for
new incoming payments.

wallet-addr
-----------
List all bitcoin addresses in wallet.

wallet-dump
-----------
Dump entire wallet contents, including all private keys.

wallet-info
-----------
Informational summary of wallet data.

