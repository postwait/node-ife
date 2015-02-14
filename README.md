## IFE ##

IFE is (network) interface management for Node.js.  It works on Linux, Illumos, FreeBSD, MacOS X.

    var IFEdriver = require('ife'),
        ife = new IFEdriver();

### API ###

    var success =
    ife.up({ name:      "eth0",
             ip:        "10.10.10.11",
             broadcast: "10.10.10.255",
             netmask:   "255.255.255.0",
             network:   "10.10.10.0"
    });

    ife.up({ name:      "e1000g0",
             ip:        "2607:f8b0:4002:c09::64',
             prefixlen: 64
    });

Brings up the specified address on the interface "eth0".

    var success =
    ife.down('10.10.10.11');

Brings down the logical interface with the IP address 10.10.10.11.

    var ifaces = ife.list()

List all the broadcast-capable interfaces on the server.

    var ip2mac = ife.arpcache();

Returns an hash of IPs and their corresponding MAC addresses in the local server's ARP table.

    var count = 2,
        do_ping = true;

    var sent =
    ife.gratarp({ name: "eth0", local_ip: "10.10.10.11",
                  remote_ip: "10.10.10.1" }, count);

    var sent =
    ife.gratarp({ name: "eth0", local_ip: "10.10.10.11",
                  remote_ip: "10.10.10.1", remote_mac: "7c:d1:c3:dc:dd:f7" },
                count, do_ping);

Send (two) gratuitous ARP responses to 10.10.10.1 advertising our 10.10.10.11.  Second, send the same, but explicitly to the target MAC address.  By specifying a MAC address, we may also ping, which we elect to do.
