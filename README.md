# libsocks6msg
SOCKS 6 message library

## Building the library

You will need the following packages:
 * qt5-qmake
 
Afterwards, simply run:

```
qmake
make
sudo make install
```

By default, everything is placed in /usr/local. You can edit socks6msg.pro to change that.

## Differences from the standard

Because SOCKS 6 is still subject to change, apps linked against different versions of this library may use different wire formats.
To avoid such miscommunication, this implementation uses a non-standard value for the version field.
The number will change whenever a new specification is released.
