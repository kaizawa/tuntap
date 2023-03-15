# Solaris(h) TUN/TAP Driver

This is a TAP driver for Solaris, OpenIndiana, SmartOS, and other OpenSolaris
derivatives that can be used for:

* [OpenVPN](http://openvpn.net/)
* [OpenConnect](http://www.infradead.org/openconnect.html)
* [vpnc](http://www.unix-ag.uni-kl.de/~massar/vpnc/)
* [Wireguard](https://www.wireguard.com/)
* etc.

The code is based on the
[Universal TUN/TAP driver](http://vtun.sourceforge.net/tun/).
Kazuyoshi Aizawa made changes and added support for Ethernet tunneling,
since Universal TUN/TAP driver for Solaris only supports IP tunneling
known as TUN.

## Building

    tar xvfz tuntap.tar.gz
    ./configure
    make
    sudo make install
