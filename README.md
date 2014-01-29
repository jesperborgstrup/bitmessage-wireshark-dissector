bitmessage-wireshark-dissector
==============================

A Wireshark dissector for Bitmessage protocol messages written in Lua

During my research of the Bitmessage protocol, I decided that it would be useful to be able to dissect the network packages to and from the Bitmessage client in Wireshark.

Apparently, no one had created a Wireshark dissector for Bitmessage before, so I did just that in Lua and am sharing the result publicly on GitHub.

It can currently recognize the the version, verack, addr, inv, and getdata message types as well as the getpubkey, pubkey, msg, and broadcast object types.

Of course, it is only possible to view the unencrypted message with this dissector.

See the related blog post at https://jesper.borgstrup.dk/2014/01/bitmessage-protocol-dissector-for-wireshark/
