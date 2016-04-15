CPUMiner-opt
============

This is a multi-threaded CPU miner, fork of [pooler](//github.com/pooler)'s cpuminer (see AUTHORS for list of contributors).

This specific fork has AES optimizations for many algorithms, they are automatically used if your compiler, your CPU and the algorithm in question support it.

How to build
------------

```bash
git clone https://github.com/hmage/cpuminer-opt
cd cpuminer-opt
sudo apt-get install libssl-dev libcurl4-openssl-dev libjansson-dev
./build.sh
```

The resulting binary will be named `cpuminer`.

Requirements
------------

 * CPU that supports SSE2.
 * Linux.
 * Recent enough gcc that supports `-march=native`.

Algorithms
----------
 * ✓ __scrypt__ (Litecoin, Dogecoin, Feathercoin, ...)
 * ✓ __scrypt:N__
 * ✓ __sha256d__ (Bitcoin, Freicoin, Peercoin/PPCoin, Terracoin, ...)
 * ✓ __axiom__ (Axiom Shabal-256 based MemoHash)
 * ✓ __blake__ (Saffron [SFR] Blake-256)
 * ✓ __bmw__ (Midnight [MDT] BMW-256)
 * ✓ __cryptonight__ (Bytecoin [BCN], Monero)
 * ✓ __cryptonight-light__ (Aeon)
 * ✓ __dmd-gr__ (Diamond-Groestl)
 * ✓ __fresh__ (FreshCoin)
 * ✓ __groestl__ (Groestlcoin)
 * ✓ __lyra2RE__ (Lyrabar, Cryptocoin)
 * ✓ __lyra2REv2__ (VertCoin [VTC])
 * ✓ __myr-gr__ (Myriad-Groestl)
 * ✓ __neoscrypt__ (Feathercoin)
 * ✓ __nist5__ (MistCoin [MIC], TalkCoin [TAC], ...)
 * ✓ __pentablake__ (Joincoin)
 * ✓ __pluck__ (Supcoin [SUP])
 * ✓ __quark__ (Quarkcoin)
 * ✓ __qubit__ (MyriadCoin [MYR])
 * ✓ __skein__ (Skeincoin, Myriadcoin, Xedoscoin, ...)
 * ✓ __skein2__ (Woodcoin)
 * ✓ __s3__ (OneCoin)
 * ✓ __scrypt-jane__ (YaCoin, CopperBars, Pennies, Tickets, etc..)
 * ✓ __x11__ (Darkcoin [DRK], Hirocoin, Limecoin, ...)
 * ✓ __x13__ (Sherlockcoin, [ACE], [B2B], [GRC], [XHC], ...)
 * ✓ __x14__ (X14, Webcoin [WEB])
 * ✓ __x15__ (RadianceCoin [RCE])
 * ✓ __zr5__ (Ziftrcoin [ZRC])

#### Implemented, but untested
 * ? blake2s
 * ? hefty1 (Heavycoin)
 * ? keccak (Maxcoin, HelixCoin, CryptoMeth, Galleon, 365coin, Slothcoin, BitcointalkCoin)
 * ? luffa (Joincoin, Doomcoin)
 * ? shavite3 (INKcoin)
 * ? sib (SibCoin)
 
Dependencies
------------
 * libcurl http://curl.haxx.se/libcurl/
 * jansson http://www.digip.org/jansson/
 * openssl https://www.openssl.org/

Easiest way to get them on Debian-based distributions is to run:
```bash
sudo apt-get install libssl-dev libjansson-dev libcurl4-nss-dev
```

Usage instructions
------------------
Run `cpuminer --help` to see options.

### Connecting through a proxy

Use the `--proxy` option.

To use a SOCKS proxy, add a `socks4://` or `socks5://` prefix to the proxy host .

Protocols `socks4a` and `socks5h`, allowing remote name resolving, are also available since libcurl 7.18.0.

If no protocol is specified, the proxy is assumed to be a HTTP proxy.  
When the `--proxy` option is not used, the program honors the http_proxy and all_proxy environment variables.

Donations
---------
Donations for the work done in this fork are accepted:

Tanguy Pruvot :
* BTC: `1FhDPLPpw18X4srecguG3MxJYe4a1JsZnd`
* ZRC: `ZX6LmrCwphNgitxvDnf8TX6Tsegfxpeozx`

Lucas Jones :
* MRO: `472haywQKoxFzf7asaQ4XKBc2foAY4ezk8HiN63ifW4iAbJiLnfmJfhHSR9XmVKw2WYPnszJV9MEHj9Z5WMK9VCNHaGLDmJ`
* BTC: `139QWoktddChHsZMWZFxmBva4FM96X2dhE`

Jay D Dee:
* BTC: `12tdvfF7KmAsihBXQXynT6E6th2c2pByTT`

HMage:
* BTC: `1HMageKbRBu12FkkFbMEcskAtH59TVrS2G`

Credits
-------
CPUMiner-multi was forked from pooler's CPUMiner, and has been started by Lucas Jones.
* [tpruvot](https://github.com/tpruvot) added all the recent features and newer algorythmns
* [Wolf9466](https://github.com/wolf9466) helped with Intel AES-NI support for CryptoNight

License
-------
GPLv2.  See COPYING for details.
