# HXARK Sniffer

WoW Retail packet capture for Windows. Detects the network interface and saves PKT files for [WowPacketParser](https://github.com/TrinityCore/WowPacketParser).

**Beta: Retail 12.1.5 builds 70575, 70688 and 70783, Windows x64, IPv4.**

## Use

1. Open the sniffer and wait for **Ready**.
2. Open WoW, log in and play.
3. Close WoW. PKTs save automatically. Click **Open captures** to find them.

You can leave the sniffer open between sessions. Select `Wow.exe` once if it is not found. If capture support is missing, use the setup button and keep Npcap selected in the Wireshark installer.

The EXE runs without Python or an account. Captures stay on your PC.

The sniffer captures and saves PKTs. Parse saved files separately with WPP;
the sniffer does not include, install or run the parser.

PKTs are saved in `%LOCALAPPDATA%\HXARK\Sniffer\dumps`. Keep recovery files and session keys private.

## Build

Windows x64, Python 3.14 with Tcl/Tk:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe scripts/build_sniffer_staff.py
```

Output: EXE, SHA-256 and build manifest in `dist`. To run from source:

```powershell
.\.venv\Scripts\python.exe scripts/sniffer_staff.py
```

## Compatibility

New WoW builds need tested profiles. Updates are manual: replace the EXE.

A session can produce several PKTs. Filenames use known area names or numeric IDs. WPP parsing is partial; unsupported messages remain in the capture. Interrupted captures are reported as incomplete.

New captures include the capture PC's UTC offset, absolute packet timestamps and
separate connection identifiers in the PKT 3.1 extensions supported by WPP. The
text locale is read from the game's `WTF/Config.wtf`; the local receipt records
when `enUS` had to be used as a fallback. UTC offset is recorded when WoW is
detected, including the daylight-saving offset then in effect.

Capture and metadata recording are automatic. Open the sniffer, wait for Ready,
play WoW, then close the game to save your PKTs. No manual packet annotations or
parser installation are required.

Each new PKT has an optional `.pkt.capture.json` quality receipt beside it,
linked by SHA-256. It records the build, connection, counts and capture status,
without session keys, network addresses or account details. Keep it with the
PKT for quality checks. Standard WowPacketParser reads the PKT directly and
does not need the receipt.

Location filenames are recognized for all three supported builds.

The receipt includes final capture-driver drop counts when available. Unavailable
counters stay unknown. Detected IPv6 game connections are reported as unsupported;
they are not captured. These checks do not prove that all game traffic was observed.

Capture limits: 12 hours from WoW detection, 1 GiB input, 1 million candidate
packets, 8 interfaces, 32 flows per interface and 32 session-key snapshots.
Input and packet limits are divided between interfaces. The app warns before
these limits; it keeps recovery data if a capture stops early.

EXEs are not Authenticode signed. Use only on sessions you are authorized to capture.

## License

[MIT](LICENSE). Dependency licenses and protocol references are listed in [NOTICE](NOTICE).

By [HXARK](https://hxark.com). Not affiliated with Blizzard, Wireshark or Npcap.
