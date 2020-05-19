# ghidra-stm32

This is a loader for the STM32F2 series of microcontrollers

## What it does
* Labels memory regions
* Labels IVT and entry point (assuming normal boot mode)
* Labels USB-OTG Configuration registers

## Installation
You can install the loader via a zip on the releases page, or build the module yourself following instructions from the blog post

## Building with eclipse
After configuring Eclipse with the GhidraDev extension, this project can be built in Eclipse

## Building with gradle

You just need Java, gradle and ghidra for building. Position in source dir and issue gradle command:

```
gradle -PGHIDRA_INSTALL_DIR=/opt/ghidra_9.1.2_PUBLIC
```

You can check what tasks you can also call with gradle with standard tasks options:

```
gradle tasks -PGHIDRA_INSTALL_DIR=/opt/ghidra_9.1.2_PUBLIC
```

Note: you can also put path to the ghidra in gradle.properties file:
```
GHIDRA_INSTALL_DIR=/opt/ghidra_9.1.2_PUBLIC
```

