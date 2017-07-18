# Goal

The goal of this project is to write an Android RIL daemon implemented on top of [oFono](https://01.org/ofono), with a focus on supporting Qualcomm phones.

# Roadmap

1. Alpha implementation in Java
	1. For simplicity, it will run on Linux but keep Android compatibility in mind (targeting a Dalvik command-line app)
	1. For simplicity, oFono will also be running on Linux
	1. The oFono instance will be using the `rilmodem` driver. Yes, this first version of the RIL will be built on a RIL! This will hopefully mean fewer "moving parts" and missing functionality to start, allowing us to focus on the basic architecture.
	1. The `rild` sockets for the original RIL and this one will be mapped over something like `adb forward` so it's transparent
1. Port the new `rild` to run on Android on-device
	1. Write `Android.mk` file, init script to run it, make any tweaks for the runtime subset that Android has
1. Port oFono to Android on-device
	1. This old port might help: https://github.com/nitdroid/platform_external_ofono
1. Pivot oFono onto the `qmimodem` driver
	1. May need to write an interface for `qmuxd`, or stop using it at that point (this may kill other hardware)
1. Implement missing features in oFono's `qmimodem` (e.g. voice calls)
	1. At this point we may hit some serious walls in regards to reverse-engineering this stuff. If that's a showstopper, I hope the work can still be useful to someone who wants to run an open Android RIL on a platform oFono supports better.
1. Port to another language? (Rust, go? I'm sticking to Java to lower my learning curve and workload for now.)