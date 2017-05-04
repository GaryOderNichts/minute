# Minute CFW
© 2016-2017 SALT. See COPYING for details.
This is a mirror just in case the [original copy](https://github.com/Dazzozo/minute) disappears for some reason.

## What is it?
It is a CFW solution for the Wii U, providing a modified console firmware that allows your Wii U console to perform actions it was not supposed to. It is a complete re-implementation of Nintendo's IOSU operating system, based on Mini from the Wii days. It does not provide much functionality on its own, see the features section below.

## Building
Unlike other CFW solutions released for the Wii U, this one has no special dependencies. All you need to successfully build this is devkitARM, Python 3 and PyCrypto. Then it is as simple as running `make` to build it.

While these scripts will give you an `fw.img` file at the end, it does not require an official Nintendo `fw.img` in order to build. This means that the final image is built from scratch, and does not have any Nintendo copyrighted code. It is also not encrypted using Nintendo copyrighted keys, making it perfectly legal (I think) to distribute in binary form.

## Features
Minute is not really a CFW within itself. It loads various secondary images from the SD Card and executes them on the ARM (a.k.a. Starbuck/IOSU) processor.

From a quick glance at the source code (I'm not with my console right now, so I cannot test this), it seems to have many features, such as bootstrapping the PowerPC processor with a custom program, 
providing access to the SD Card and NAND memory, reading (but not editing) SEEPROM memory and access to the GPIO and I2C features of the Wii U.
