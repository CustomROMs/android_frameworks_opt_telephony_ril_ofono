# Goal

The goal of this project is to write an Android RIL daemon implemented on top of [oFono](https://01.org/ofono), with a focus on supporting Qualcomm phones.

# Roadmap

1. Alpha implementation in Java
	1. Write a RIL class that the com.android.phone app (via the telephony framework) will load. This class will interface with oFono.
	1. The oFono instance will be using the `rilmodem` driver. Yes, this first version of the RIL will be built on a RIL! This will hopefully mean fewer "moving parts" and missing functionality to start, allowing us to focus on the basic architecture.
1. Pivot oFono onto the `qmimodem` driver
	1. May need to write an interface for `qmuxd`, or stop using it at that point (this may kill other hardware)
1. Implement missing features in oFono's `qmimodem` (e.g. voice calls)
	1. At this point we may hit some serious walls in regards to reverse-engineering this stuff. If that's a showstopper, I hope the work can still be useful to someone who wants to run an open Android RIL on a platform oFono supports better.
1. Port to another language? (Rust, go? I'm sticking to Java to lower my learning curve and workload for now.)

# Usage
1. System patches
	* See `patches` file for pseudo-patches to get an idea of what I'm running
		* Patch telephony framework to be able to load the RIL class from another package
	* system/core/rootdir/init.rc - add dbus and ofono services
	* install dbus conf file in /system/etc/dbus.conf
	* sepolicy updates for dbus and radio interop
1. Build from CM12.1 checkout with [this manifest](https://github.com/scintill/android/commit/424776d7635ddfae3591516e032cc5820f1dfc1a)
	* `mmm ~/ril_ofono`
	* (Might depend on the rest of android or at least RIL having been built before.)
1. Running
	* Execute the `start` script in the root directory.
	* Getting ofono up can be a bit of an ordeal, on my device at least, due to [apparent timing issues with the rilmodem backend](https://lists.ofono.org/pipermail/ofono/2017-August/017355.html) (my post), so it looks something like this:
		* `adb shell stop`
		* `adb shell start ofonod-debug`
		* `adb shell dbus-send --print-reply --system --dest=org.ofono /ril_0 org.ofono.Modem.SetProperty string:"Online" variant:boolean:"true"`
		* \# look for a bunch of SIM I/O calls in oFono logs. If not, `adb shell killall ofonod` and try the dbus-send again.
		* `./start`
		* `adb shell start`
1. Debugging
    * You can forward the dbus to your PC: `adb forward localfilesystem:/tmp/dbus-android localreserved:dbus`. Then use the dbus address `unix:path=/tmp/dbus-android` for dbus-send, d-feet, etc.
    * Look for log tags `RilOfono`, `OfonoUtils`, and `ofonod` (all in the radio log)

# Features

Nothing is thoroughly tested nor tried on a broad selection of hardware/networks yet.

* Basic SMS sending and receiving
	* Has issues with long messages (sending a long message will work, but it will arrive fragmented; receiving a long one will not work at all); see TODO below
* Basic voicecalls: dialing, receiving, answering, rejecting
	* On my device, oFono seems unable to give Line ID (I think it's a RIL parcel mismatch), so numbers are displayed as "Unknown"
* User-intiated USSD (special dial codes, such as `#999#` which displays balance on my carrier)
* Basic data connections
	* Might be a little flaky; see TODO below
* Reporting of phone #, ICCID, voicemail # to Android

# Resources and Credit
* https://github.com/nitdroid/ofono-ril for some help on mapping ofono properties to Android RIL

# Bugs and TODO
* SMS send/receive - current implementation is limited when it comes to things like long messages. We could
concatenate/split PDUs in the RIL to map on to Ofono's nice API, but we will not be able to implement a few things
that raw PDUs can do. And duplicating the work is ugly anyway, so I think I will just patch Ofono with raw PDU APIs.
* look at and fix flaky data call setup. It seems the framework doesn't ask us to set up a connection, even if the user toggles the data slider.
	* Toggling airplane mode, or restarting com.android.phone with the slider on, may help as workarounds.
	* Also, turning off wifi may be needed to make sure the framework has a reason to enable mobile data
* make dbus exceptions be checked exceptions, so the compiler will find them and I have to handle them
* dexopt/proguard? - see notes in Android.mk
* crashes in airplane mode trying to query properties on probably not-up interfaces

# License

> ril_ofono is free software: you can redistribute it and/or modify
> it under the terms of the GNU General Public License as published by
> the Free Software Foundation, either version 3 of the License, or
> (at your option) any later version.

> ril_ofono is distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
> GNU General Public License for more details.

> You should have received a copy of the GNU General Public License
> along with ril_ofono.  If not, see <http://www.gnu.org/licenses/>.
