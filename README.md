# BGP Scanner

The Isolario MRT data reader utility.

A performance oriented utility to parse MRT RIB snapshots and updates,
with filtering capability.

[Homepage](https://isolario.it)

## Building

BGP Scanner uses [Meson](https://mesonbuild.com) to manage the build process.

The basic steps for configuring and building BGP Scanner look like this:

```bash
$ git clone https://gitlab.com/Isolario/bgpscanner.git
$ cd bgpscanner
$ mkdir build && cd build
$ meson ..
$ ninja
```

Note that BGP Scanner requires the Isolario
[isocore](https://gitlab.com/Isolario/isocore.git) BGP and MRT library to
build and run. This dependency is fetched and built automatically by Meson in
case they are not already available in your system.

In case you want to build the *release* configuration of BGP Scanner, just
enable the *release* build type, like this:

```bash
$ git clone https://gitlab.com/Isolario/bgpscanner.git
$ cd bgpscanner
$ mkdir build && cd build
$ meson --builtype=release ..
$ ninja
```

Or run the following inside the build directory

```bash
$ meson configure -Dbuiltype=release
$ ninja
```

## Installation Guide

For Ubuntu and Debian Based System

First make sure you have git and meson installed (If not please install them)

```bash
sudo apt install git meson-build
```

Make sure to install the necessary dependencies to build the isocore Isolario
BGP and MRT library:

```bash
sudo apt install zlib1g-dev libbz2-dev liblzma-dev liblz4-dev
```

Now, let's clone the repository and build it:

```bash
git clone https://gitlab.com/Isolario/bgpscanner.git
cd bgpscanner
mkdir build && cd build
meson --buildtype=release ..
ninja
```

If you need to install BGP Scanner globally

```
sudo ninja install
```
