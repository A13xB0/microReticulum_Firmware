# microReticulum_Firmware

Fork of RNode_Firmware with integration of the [microReticulum](https://github.com/attermann/microReticulum) Network Stack to implement a completeley self-contained standalone Reticulum node.

## Installation

This firmware can be easily installed on devices in the same way as RNode using the new `fw-url` switch to `rnodeconf` which allows firmware images to be pulled from an alternate repository. RNS may need to be updated to the latest version to use this new switch.

The latest version of this firmware can be installed in the usual RNode way with the following command:
```
rnodeconf --autoinstall --fw-url https://github.com/attermann/microReticulum_Firmware/releases/
```

NOTE: If re-installing a new build of the same version installed previously, be sure to clear the rnodeconf cache first to force it to download the very latest.
```
rnodeconf --clear-cache
```

## Enabling Transport Mode

By default this firmware will operate just like any other RNode firmware allowing it to be used as just a radio by RNS installed on an attached machine.

To enable `Transport Mode` using the RNS embedded on the device, the device must be switched to TNC mode using a command like the following:
```
rnodeconf --tnc --freq 915000000 --bw 125000 --sf 8 --cr 5 --txp 17 /dev/ttyACM0
```
When in `Transport Mode`, the device will display "TRANSPORT" across the top of the AirTime panel of the display to indicate that the embedded RNS is active and routing packets.

Note that at the present time, when in TNC mode this firmware does not operate like a regular RNode does when in TNC mode due to logging from the embedded RNS that is output on the serial port. This can clobber KISS communication from the attached machine so do not attempt to attach another RNS to the device while in this mode. On the plus side, there is extensive logging available on the serial port to observe the embedded RNS in action and to aid in troubleshooting.

## Build Dependencies

Build environment is configured for use in [VSCode](https://code.visualstudio.com/) and [PlatformIO](https://platformio.org/).

## Building from Source

Building and uploading to hardware is simple through the VSCode PlatformIO IDE
- Install VSCode and PlatformIO
- Clone this repo
- Lanch PlatformIO and load repo
- In PlatformIO, select the environment for intended board
- Build, Upload, and Monitor to observe application logging

Uploading to devices requires access to the `rnodeconf` utility included in the official [Reticulum](https://github.com/markqvist/Reticulum) distribution to update the device firmware hash. Without this step the device will report invalid firmware and will fail to fully initialize.

Instructions for command line builds and packaging for firmware distribution.

## Build Options

- `-DHAS_RNS` Used to enable the microReticulum RNS stack and transport node.
- `-DUDP_TRANSPORT` Used to enable WiFi connection (when configured through `rnodeconf` as an additional transport medium (currently hard-coded to use port 4242).

## PlatformIO Command Line

Clean all environments (boards):
```
pio run -t clean
```

Full Clean (including libdeps) all environments (boards):
```
pio run -t fullclean
```

Build a single environment (board):
```
pio run -e ttgo-t-beam
pio run -e heltec-wireless-tracker-v2
pio run -e wiscore_rak4631
```

Build and upload a single environment (board):
```
pio run -e ttgo-t-beam -t upload
pio run -e heltec-wireless-tracker-v2 -t upload
pio run -e wiscore_rak4631 -t upload
```

Build and package a single environment (board):
```
pio run -e ttgo-t-beam -t package
pio run -e heltec-wireless-tracker-v2 -t package
pio run -e wiscore_rak4631 -t package
```

On erased EEPROM, the Heltec Wireless Tracker V2 enables BLE and explicitly
disables Wi-Fi; later user choices are preserved. Radio parameters remain unset
until a user selects region-appropriate values.

Build all environments (boards):
```
pio run
```

Build and package all environments (boards):
```
pio run -t package
```

Write version info:
  python release_hashes.py > Release/release.json

## Firmware Release

New firmware release procedure:

  1. Ensure that microReticulum repo is updated for build (and package versioning is incremented if changed)

  2. Shutdown microReticulum_Firmware project in IDE (if open)

  3. Clean build directory
     ```
     pio run -t fullclean
     ```

  4. Clean release directory
     ```
     rm Release/release.json
     ```

  5. Build new releases
     ```
     pio run -t package
     ```

  6. Upload all files (except README.md and esptool) to github release

## Provisioning System and RNode Console

This firmware adds a structured **Provisioning** subsystem on top of the legacy RNode KISS protocol and a single-page web app — the **RNode Console** — that drives it. Together they replace ad-hoc `rnodeconf` invocations for day-to-day setup and give the same view of a node whether you are sitting next to it with a USB cable or several LoRa hops away.

For an end-user walkthrough (including remote management and per-transport caveats) see [docs/Provisioning.md](docs/Provisioning.md).

### Provisioning subsystem

The Provisioning subsystem is a typed, namespaced configuration engine running inside the embedded microReticulum stack. Each settable item (LoRa interface mode, NomadNet site name, KISS-framed logging, etc.) is declared as a field with a type, flags (`LIVE_APPLY`, `REBOOT_REQUIRED`, `READ_ONLY`, `WRITE_ONLY`, `SECRET`), and a setter/getter. Live metrics (radio link, channel utilisation, RNS destination hashes, WiFi info) are surfaced through the same engine as read-only fields. A draft/commit model — `SetState` → `Commit` (or `Discard`) — means changes are staged before they touch the device, with reboot-required changes flagged separately. Persisted state is stored in MsgPack files alongside Reticulum's path table. See `Provisioning.h` / `Provisioning.cpp` and the `RNS_USE_PROVISIONING` / `RNS_ENABLE_REMOTE_PROVISIONING` build flags for the wire protocol.

Crucially, the same wire protocol is available **locally** (KISS-framed over USB / BLE / WiFi WebSocket) and **remotely** (carried over a Reticulum Link to the node's `rnstransport.remote.management` destination), so the node can be configured from anywhere it can be reached on the mesh.

### RNode Console (web UI)

The RNode Console is a single-page web app (sources in `webconsole/index.html`, packaged delivery artifact in `Release/console.html`) that speaks the Provisioning protocol directly from the browser. It runs entirely client-side — no backend other than the node itself. Open `Release/console.html` from disk (or host it from any static web server) and pick a transport:

| Transport | Use case | Requires |
|-----------|----------|----------|
| **Serial** | Direct USB connection (sitting at the node) | Chrome / Edge / latest Firefox with Web Serial |
| **Bluetooth** | BLE-equipped boards in range | Chrome / Edge / latest Firefox with Web Bluetooth |
| **WebSocket** | Node on the LAN over WiFi | Node in WiFi STA/AP mode and reachable on port 81 (embedded) / 8080 (native) |
| **RNS (via rnsapid)** | Remote node anywhere on the Reticulum mesh | A locally running [ReticulumAPI](https://github.com/attermann/ReticulumAPI) instance exposing the `link.*` WebSocket API |

Features available through the Console:

- **Node Status** — live radio link metrics (RSSI, SNR, noise floor), channel utilisation, PHY parameters, CSMA, battery / temperature, device info (board / platform / MCU / firmware), and Danger Zone actions (Reboot, Factory reset).
- **Node Config** — legacy RNode opcodes (radio, Bluetooth, WiFi, display, EEPROM) using the same KISS commands `rnodeconf` issues, exposed in a structured form with set-only badges where the firmware has no read counterpart.
- **Transport Config** — the live Provisioning namespace tree (Reticulum, Transport, General, Metrics, optional Radio) rendered from the schema the device advertises. Edits are staged in a per-namespace draft and saved with explicit Save / Revert / Commit-all controls; reboot-required changes raise a persistent reboot banner.
- **Logs** — KISS-framed log frames streamed from the device in real time (not available over the RNS transport, which forwards only Provisioning frames).
- **Auto-reconnect** across reboots so early-boot logs are captured.

### Activating the web console on the device

The embedded web console (HTTP on port 80, KISS-over-WebSocket on port 81) is started by **quick-rebooting the device twice**. The first reboot stores a marker in the LoRa modem; the second reboot detects it and brings up a WiFi AP named after the device. Connect to that AP and point a browser at `http://10.0.0.1/`. On `native` builds the KISS-over-WebSocket endpoint is exposed on port 8080 — see the Native daemon section below.

> NOTE: To access a node on the LAN from the browser, Chrome's [Local Network Access Checks](chrome://flags/#local-network-access-check) flag may need to be temporarily disabled depending on your Chrome version.

### Building the web console artifact

The packaged delivery artifact is produced by `webconsole/package.sh`, which slices the `?selftest=1` block and runs the result through `html-minifier-terser`:

```
webconsole/package.sh           # default: strip comments + whitespace
webconsole/package.sh --minify  # full minification with JS identifier mangling
```

Output lands in `Release/console.html` by default. The same artifact is baked into the embedded firmware via `Console/build.py`.

## Seeed SenseCAP Solar Node P1

`env:seeed_solar_node_p1` targets the [SenseCAP Solar Node P1](https://wiki.seeedstudio.com/meshtastic_solar_node/) (and P1-Pro): a XIAO nRF52840 Plus with a Wio-SX1262, a 5 W panel and four 18650 cells in a weatherproof box — a standalone, unattended Reticulum transport node with no host computer.

- **Hardware definitions** come from the Meshtastic (`variants/nrf52840/seeed_solar_node`) and MeshCore (`variants/sensecap_solar`) targets, which agree on every pin: SX1262 on SPI0 (SCK P1.13 / MISO P1.14 / MOSI P1.15), CS P0.04, DIO1 P0.03, RESET P0.28, BUSY P0.29, RXEN P0.05 with DIO2 as the TX switch, DIO3 TCXO at 1.8 V. See `variants/seeed_solar_node_p1/` and the `BOARD_SEEED_P1` block in `Boards.h`.
- **Persistence** uses the on-board 2 MiB P25Q16H over the nRF52840's QSPI peripheral, so the path table is not limited by InternalFS's 28 KB. Requires the `qspi-transport` branch of microStore (an added constructor that accepts an external `Adafruit_FlashTransport`).
- **Battery**: the 18650 pack is read through the board's 1 M / 512 k divider on P0.31 (enabled by P0.14). Voltage, percentage and charge state are available in the RNode Console (USB, BLE, or remotely over Reticulum via the Provisioning **Power** metrics), on the NomadNet stats page, and in `rnodeconf --info`. Calibrate `P1_VBAT_DIVIDER` in `Power.h` against a meter if needed.
- **SoftDevice**: Seeed ships S140 **7.3.0**, so this env links with `boards/nrf52840_s140_v7.ld` and the SD7 headers under `lib/nrf52/` (both from MeshCore). Do not use the v6 script the RAK targets use.
- **Provisioning**: the board is registered as `PRODUCT_RAK4631` / `MODEL_12` (same MCU, radio and band class) so a stock `rnodeconf` accepts it. Bootstrap with `rnodeconf --platform nrf52 --product 10 --model 12 --hwrev 1 <port>` after the first upload; the PlatformIO post-upload step writes the firmware hash.
- **Flashing**: double-tap RESET (XIAO-BOOT), then `pio run -e seeed_solar_node_p1 -t upload`, or `pio run -e seeed_solar_node_p1 -t package` and drag `Release/*.uf2` onto the XIAO-BOOT drive. The DFU zip carries `--sd-req 0x0123` for SD 7.3.0.
- The P1-Pro's L76K GPS is held powered off; there is no GPS support in this firmware. Deep sleep is not implemented for this board yet.

## Native Daemon Support

In addition to the embedded ESP32 / nRF52 firmware images, the project now builds two **native** targets backed by Meshtastic's [platform-native](https://github.com/meshtastic/platform-native) (Portduino). These produce a real binary you can run on a host machine — useful for development without a board attached, and for running a self-contained Reticulum transport node on small Linux SBCs.

### Targets

| PlatformIO env | Backend | Purpose |
|----------------|---------|---------|
| **`native-macos`** | Portduino simulated SPI / GPIO (returns zeros) | Dev iteration on macOS without any radio hardware. Launches with `-ULORA_TRANSPORT`, so no Reticulum interface is registered — the binary boots, exposes the Provisioning + web console surfaces, and otherwise idles. |
| **`native`** | Portduino Linux backend (`libgpiod` + `/dev/spidev`) | Real Reticulum transport daemon on Linux. Drives a SX1262 / SX1276 / SX1278 / SX1280 LoRa radio over a real SPI bus and real GPIO lines. |

Both share `lib_deps`; Portduino's `#ifdef __linux__` guards pick the simulated vs real backend at compile time.

### Features

- **Same firmware, same protocols.** The native build is the same `RNode_Firmware.ino` codebase as the embedded targets; the Provisioning subsystem, microReticulum stack, NomadNet stats pages, and legacy KISS opcodes all behave identically.
- **`rnoded.conf` runtime configuration.** Pin map, GPIO chip, SPI device + speed, LoRa modem family + parameters, TCXO voltage, RF-switch behaviour, auxiliary "radio enable" pins, and TX-failure recovery are all read at startup from a key=value text file. See `rnoded.example.conf` for the full schema. Overrides: `--config PATH` / `-c PATH` on the command line, or `$MR_CONFIG`. The data directory (where Reticulum's path store, the EEPROM image, etc. live) is set by `data_dir` in the config or `$MR_DATA_DIR`.
- **Self-provisioning EEPROM.** On first boot, `native/PinMap.cpp::seed_eeprom_if_unprovisioned()` seeds the EEPROM image so `rnodeconf` is not needed to bring the daemon up. The rnodeconf-style MD5 firmware-image check is bypassed (`-DDISABLE_FIRMWARE_CHECKSUM`).
- **KISS over localhost TCP.** The embedded USB-serial KISS channel is replaced by a TCP server (default `127.0.0.1:7633`). Tools that would normally open `/dev/ttyACM0` (rnodeconf, RNS `KISSInterface`) connect to that socket instead. Loopback by default; `kiss_tcp_public = true` in `rnoded.conf` opts into binding `0.0.0.0`.
- **KISS over WebSocket** on port 8080 so the RNode Console can drive the daemon from a browser. Same loopback-by-default model — `kiss_ws_public = true` opens it up.
- **Forced TNC mode.** The native daemon boots with `op_mode = MODE_TNC` so the Reticulum Transport runs in routing mode without needing a host to flip the bit.
- **Re-exec on reboot.** A `Reboot` from the Console (or any other source) re-execs the daemon in place — the cwd is captured at launch so the child resolves `rnoded.conf` against the same directory.
- **Systemd-ready.** A reference unit file is included (`rnoded.example.service`) — drop a copy into `/etc/systemd/system/` and adapt the user/working directory.

### Supported host platforms

- **macOS (Apple Silicon / Intel)** via `native-macos`. Builds on macOS only; needs `argp-standalone` (`brew install argp-standalone`) because Apple's libc lacks `argp.h`. The simulated SPI / GPIO backend means no LoRa traffic actually flows, but everything else — provisioning, KISS over TCP + WebSocket, the web console, microReticulum's path store — runs end-to-end.
- **Linux** via `native`. Tested on Raspberry Pi (Bookworm), FemtoFox, and LuckFox Pico (Mini / Plus). Any Linux host with `libgpiod` and `/dev/spidev` will work as long as a supported SX12xx modem is wired to it. Cross-build environments for Debian Bookworm and Ubuntu Jammy on amd64 / arm64 / armhf are provided under `docker/`.

Common HATs / wirings are documented in `rnoded.example.conf`, including RAK6421 + RAK13302 (SX1262 with PA), the Waveshare SX126x LoRa HAT, and LuckFox Pico + RFM95x (SX1276).

## Roadmap

- [x] Extend KISS interface to support config/control of the integrated microReticulum stack
- [x] Add interface for easy customization of firmware
- [ ] Add power management and sleep states to extend battery runtime
- [x] Add build targets for NRF52 boards

Please open an Issue if you have trouble building or using the firmware or daemon, and feel free to start a new Discussion for anything else.

## Contributing

Contributions to **microReticulum_Firmware** are welcome and appreciated.

Before opening an issue or submitting a pull request, please read the project's **[CONTRIBUTING.md](CONTRIBUTING.md)** guide. It describes the expectations for bug reports, feature requests, coding standards, testing, and pull requests.

In particular, contributors are asked to:

- Clearly identify the problem being solved before describing the proposed solution.
- Keep pull requests focused on a **single logical concern**.
- Test changes thoroughly, including on **all affected platforms** when modifying shared code.
- Update documentation when introducing user-visible changes.

Following these guidelines helps streamline reviews, improve software quality, and make it easier to integrate contributions.
