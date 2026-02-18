# Input Injection & Control Surface APIs

> Research document for the Clawdstrike CUA Gateway project.
> Covers platform-specific input injection mechanisms, accessibility/control surface APIs,
> cross-platform abstractions, and the Wayland security model.

---

## Table of Contents

1. [Overview](#overview)
2. [Linux Input Injection](#linux-input-injection)
   - [uinput Kernel Module](#uinput-kernel-module)
   - [libevdev uinput Helpers](#libevdev-uinput-helpers)
   - [XTEST / XTestFakeInput (X11)](#xtest--xtestfakeinput-x11)
   - [libei (Wayland Input Emulation)](#libei-wayland-input-emulation)
3. [Windows Input Injection](#windows-input-injection)
   - [Win32 SendInput](#win32-sendinput)
   - [UIPI and Integrity Levels](#uipi-and-integrity-levels)
4. [macOS Input Injection](#macos-input-injection)
   - [Quartz Event Services](#quartz-event-services)
   - [Event Taps](#event-taps)
   - [Permission Requirements](#permission-requirements)
5. [Accessibility / Semantic Control Surfaces](#accessibility--semantic-control-surfaces)
   - [Windows UI Automation (UIA)](#windows-ui-automation-uia)
   - [macOS AXUIElement](#macos-axuielement)
   - [Linux AT-SPI](#linux-at-spi)
6. [Wayland-Specific Mechanisms](#wayland-specific-mechanisms)
   - [XDG Desktop Portal RemoteDesktop](#xdg-desktop-portal-remotedesktop)
   - [KDE Fake Input Protocol](#kde-fake-input-protocol)
   - [Wayland Security Model Deep Dive](#wayland-security-model-deep-dive)
7. [Cross-Platform Abstractions](#cross-platform-abstractions)
   - [PyAutoGUI](#pyautogui)
   - [Other Cross-Platform Libraries](#other-cross-platform-libraries)
8. [Comparison Matrix](#comparison-matrix)
9. [Implications for CUA Gateway Design](#implications-for-cua-gateway-design)
10. [References](#references)

---

## Overview

A Computer-Use Agent (CUA) gateway must translate high-level agent intents (e.g., "click the Submit button") into low-level input events that the operating system and applications process as if they came from a physical human user. The choice of injection mechanism has deep implications for:

- **Security**: Who can inject? What privilege boundaries exist?
- **Fidelity**: Are injected events indistinguishable from real hardware events?
- **Semantic richness**: Can we target UI elements by role/name rather than pixel coordinates?
- **Auditability**: Can we produce receipts that capture *what* was targeted, not just *where* we clicked?
- **Portability**: Does the mechanism work across display servers, desktop environments, and OS versions?

This document surveys the full landscape of input injection and control surface APIs across Linux, Windows, and macOS, with particular attention to the Wayland transition on Linux and its implications for CUA gateway architecture.

### Pass #2 reviewer notes (2026-02-18)

- REVIEW-P2-CORRECTION: Prefer remote-desktop protocol mediation as the default execution path; direct host injection paths should be explicitly marked as higher-risk fallback modes.
- REVIEW-P2-GAP-FILL: Add a per-platform "verification contract" after each injection call (what state must change, and how to fail closed if it does not).
- REVIEW-P2-CORRECTION: Claims about compositor support and portal behavior should be validated against current release docs before production commitments.

### Pass #2 execution criteria

- Injection success is confirmed by post-condition checks (not API return values alone).
- Every platform backend reports standardized failure classes (permission, privilege boundary, target mismatch, timeout).
- High-risk host-level injection modes require explicit policy enablement and audit tagging.
- Wayland flow includes explicit portal/session lifecycle handling and deterministic denial behavior.

### Pass #4 reviewer notes (2026-02-18)

- REVIEW-P4-CORRECTION: Distinguish "API accepted event" from "target performed intended UI action" in all backend contracts.
- REVIEW-P4-GAP-FILL: Add threat-tier defaults for injection backends (protocol-mediated first, host-level injection opt-in only).
- REVIEW-P4-CORRECTION: Platform support claims (especially compositor/libei coverage) need release-pinned validation before production commitments.

### Pass #4 implementation TODO block

- [x] Define a unified injection outcome schema (`accepted`, `applied`, `verified`, `denied`, `unknown`) with reason codes (`./injection_outcome_schema.json`).
- [x] Add backend capability manifest per platform/runtime and load it at session start (`./injection_backend_capabilities.yaml`).
- [x] Add deterministic post-condition probes for click/type/scroll/key-chord actions (`./postcondition_probe_suite.yaml`, `../../../../fixtures/policy-events/postcondition-probes/v1/cases.json`).
- [x] Add negative tests for ambiguous targets, permission revocation mid-session, and focus-steal races (`../../../../fixtures/policy-events/postcondition-probes/v1/cases.json`).

---

## Linux Input Injection

### uinput Kernel Module

**What it is.** `uinput` is a Linux kernel module that allows userspace programs to create virtual input devices. By writing to `/dev/uinput` (or `/dev/input/uinput`), a process creates a device that appears to the rest of the system exactly like a physical keyboard, mouse, touchscreen, or other HID device. Events written to this virtual device are delivered to all consumers (both userspace applications and in-kernel handlers) through the standard evdev subsystem.

**Device creation flow.**

```c
#include <linux/uinput.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);

// 1. Declare supported event types
ioctl(fd, UI_SET_EVBIT, EV_KEY);    // Key press/release events
ioctl(fd, UI_SET_EVBIT, EV_REL);    // Relative movement (mouse)
ioctl(fd, UI_SET_EVBIT, EV_ABS);    // Absolute positioning (touch)
ioctl(fd, UI_SET_EVBIT, EV_SYN);    // Synchronization events

// 2. Declare specific capabilities
ioctl(fd, UI_SET_KEYBIT, KEY_A);    // Support 'A' key
ioctl(fd, UI_SET_KEYBIT, KEY_B);    // Support 'B' key
ioctl(fd, UI_SET_KEYBIT, BTN_LEFT); // Support left mouse button
ioctl(fd, UI_SET_RELBIT, REL_X);    // Support X-axis relative movement
ioctl(fd, UI_SET_RELBIT, REL_Y);    // Support Y-axis relative movement

// 3. Configure device identity
struct uinput_setup usetup;
memset(&usetup, 0, sizeof(usetup));
usetup.id.bustype = BUS_USB;
usetup.id.vendor  = 0x1234;
usetup.id.product = 0x5678;
strcpy(usetup.name, "CUA Gateway Virtual Input");

ioctl(fd, UI_DEV_SETUP, &usetup);

// 4. Create the device
ioctl(fd, UI_DEV_CREATE);

// Device is now live in /dev/input/eventN
```

**Writing events.** Once the device is created, events are injected by writing `struct input_event` records:

```c
struct input_event ev;

// Key press: 'A'
ev.type  = EV_KEY;
ev.code  = KEY_A;
ev.value = 1;  // 1 = press, 0 = release, 2 = repeat
write(fd, &ev, sizeof(ev));

// Synchronize (marks end of an atomic event group)
ev.type  = EV_SYN;
ev.code  = SYN_REPORT;
ev.value = 0;
write(fd, &ev, sizeof(ev));

// Key release: 'A'
ev.type  = EV_KEY;
ev.code  = KEY_A;
ev.value = 0;
write(fd, &ev, sizeof(ev));

ev.type  = EV_SYN;
ev.code  = SYN_REPORT;
ev.value = 0;
write(fd, &ev, sizeof(ev));
```

**Permission model.** Access to `/dev/uinput` is controlled by standard Unix file permissions. Typically:

- The device node is owned by `root:root` with mode `0660` or `0600`.
- A udev rule can grant access to a specific group (e.g., `input` or a custom `uinput` group):
  ```
  # /etc/udev/rules.d/99-uinput.rules
  KERNEL=="uinput", GROUP="uinput", MODE="0660"
  ```
- In containerized environments, the device must be explicitly bind-mounted and appropriate capabilities (or device cgroup rules) granted:
  ```bash
  docker run --device /dev/uinput:/dev/uinput ...
  ```

**Security considerations for CUA.**

| Concern | Detail |
|---------|--------|
| Broad injection scope | Any process with `/dev/uinput` access can inject events system-wide, affecting all applications and display servers |
| No per-application targeting | uinput operates at the kernel level; events go to whoever has focus or is listening on the evdev node |
| Container isolation required | In a CUA gateway, the uinput device should only be accessible inside an isolated runtime (container/VM), never on a shared host |
| Audit trail | uinput itself produces no audit log; the gateway must capture pre/post evidence independently |
| Silent injection failures | If the virtual device is not set up with the correct capabilities, events may be silently dropped |

**Best practice for CUA gateway.** Use uinput only inside a dedicated, isolated desktop runtime (e.g., a container running Xvfb or a headless Wayland compositor). The gateway process should be the sole entity with `/dev/uinput` access, and the runtime should have no network egress except through the gateway's policy layer. Log device-level injection grants (e.g., `/dev/uinput`) as high-severity audit metadata.

---

### libevdev uinput Helpers

**What it is.** `libevdev` is a C library that wraps the Linux evdev and uinput kernel interfaces, providing a safer and more ergonomic API for virtual device creation and event injection. It is maintained by the freedesktop.org project and is the recommended way to interact with uinput in production code.

**Key API functions.**

| Function | Purpose |
|----------|---------|
| `libevdev_uinput_create_from_device()` | Create a uinput device that mirrors the capabilities of an existing `libevdev` device. Optionally manages the `/dev/uinput` fd internally when passed `LIBEVDEV_UINPUT_OPEN_MANAGED` |
| `libevdev_uinput_write_event()` | Write a single event (type, code, value) to the virtual device; handles `SYN_REPORT` framing |
| `libevdev_uinput_get_devnode()` | Returns the `/dev/input/eventN` path for the created virtual device |
| `libevdev_uinput_get_syspath()` | Returns the sysfs path for device introspection |
| `libevdev_uinput_destroy()` | Destroys the virtual device and frees resources |

**Device cloning pattern.** One of libevdev's most useful features for CUA is the ability to clone an existing device's capabilities:

```c
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>

// Create a libevdev device with desired capabilities
struct libevdev *dev = libevdev_new();
libevdev_set_name(dev, "CUA Gateway Keyboard");
libevdev_enable_event_type(dev, EV_KEY);

// Enable all standard keyboard keys
for (int k = KEY_ESC; k <= KEY_MICMUTE; k++) {
    libevdev_enable_event_code(dev, EV_KEY, k, NULL);
}

// Create the uinput device (managed fd)
struct libevdev_uinput *uidev;
int err = libevdev_uinput_create_from_device(
    dev,
    LIBEVDEV_UINPUT_OPEN_MANAGED,
    &uidev
);

if (err == 0) {
    // Inject a key press
    libevdev_uinput_write_event(uidev, EV_KEY, KEY_ENTER, 1);
    libevdev_uinput_write_event(uidev, EV_SYN, SYN_REPORT, 0);

    // Release
    libevdev_uinput_write_event(uidev, EV_KEY, KEY_ENTER, 0);
    libevdev_uinput_write_event(uidev, EV_SYN, SYN_REPORT, 0);
}

// Cleanup
libevdev_uinput_destroy(uidev);
libevdev_free(dev);
```

**Python bindings.** The `python-libevdev` package provides Pythonic access:

```python
import libevdev

dev = libevdev.Device()
dev.name = "CUA Gateway Mouse"
dev.enable(libevdev.EV_REL.REL_X)
dev.enable(libevdev.EV_REL.REL_Y)
dev.enable(libevdev.EV_KEY.BTN_LEFT)
dev.enable(libevdev.EV_KEY.BTN_RIGHT)

uinput = dev.create_uinput_device()

# Move mouse and click
uinput.send_events([
    libevdev.InputEvent(libevdev.EV_REL.REL_X, 100),
    libevdev.InputEvent(libevdev.EV_REL.REL_Y, 50),
    libevdev.InputEvent(libevdev.EV_SYN.SYN_REPORT, 0),
])

uinput.send_events([
    libevdev.InputEvent(libevdev.EV_KEY.BTN_LEFT, 1),
    libevdev.InputEvent(libevdev.EV_SYN.SYN_REPORT, 0),
])

uinput.send_events([
    libevdev.InputEvent(libevdev.EV_KEY.BTN_LEFT, 0),
    libevdev.InputEvent(libevdev.EV_SYN.SYN_REPORT, 0),
])
```

**Advantages over raw uinput.**

- Handles capability negotiation correctly (uinput silently drops unsupported capabilities; libevdev documents this behavior).
- Manages the `/dev/uinput` file descriptor lifecycle.
- Provides a consistent API across kernel versions.
- Error reporting is clearer than raw ioctl return codes.
- The device's lifetime is tied to the uinput file descriptor, and closing it will destroy the uinput device. Calling `libevdev_uinput_destroy()` before closing frees allocated resources.

---

### XTEST / XTestFakeInput (X11)

**What it is.** XTEST is an X11 extension (specified as part of X11R6.4+) that allows X clients to inject synthetic keyboard and mouse events directly into the X server's event processing pipeline. The events are treated as if they originated from physical hardware, making them indistinguishable to applications.

**Core API.**

```c
#include <X11/extensions/XTest.h>

Display *dpy = XOpenDisplay(NULL);

// Check for XTEST extension support
int event_base, error_base, major, minor;
Bool supported = XTestQueryExtension(dpy, &event_base, &error_base,
                                     &major, &minor);

// Inject a key press (keycode for 'a')
XTestFakeKeyEvent(dpy, XKeysymToKeycode(dpy, XK_a), True, CurrentTime);
XFlush(dpy);

// Inject a key release
XTestFakeKeyEvent(dpy, XKeysymToKeycode(dpy, XK_a), False, CurrentTime);
XFlush(dpy);

// Inject a mouse button press at current pointer position
XTestFakeButtonEvent(dpy, 1, True, CurrentTime);  // Button 1 = left
XFlush(dpy);

// Inject a mouse button release
XTestFakeButtonEvent(dpy, 1, False, CurrentTime);
XFlush(dpy);

// Move pointer to absolute position
XTestFakeMotionEvent(dpy, -1, 500, 300, CurrentTime);
XFlush(dpy);
```

**Convenience wrappers.**

| Function | Description |
|----------|-------------|
| `XTestFakeKeyEvent(dpy, keycode, is_press, delay)` | Inject a key press or release event |
| `XTestFakeButtonEvent(dpy, button, is_press, delay)` | Inject a mouse button press or release |
| `XTestFakeMotionEvent(dpy, screen, x, y, delay)` | Move pointer to absolute coordinates |
| `XTestFakeRelativeMotionEvent(dpy, dx, dy, delay)` | Move pointer by relative offset |
| `XTestGrabControl(dpy, impervious)` | Control whether active grabs affect fake events |

**Important behavior notes.**

- Each `XTestFakeInput()` call is a single user action: a button press and button release must be two separate calls.
- The extension is not intended to support general journaling and playback of user actions; it is designed for testing purposes.
- The `delay` parameter specifies milliseconds to wait before the event is processed (0 or `CurrentTime` = immediate).

**Security implications.**

The X11 trust model is fundamentally permissive: **any client connected to the X server can use XTEST to inject events into any other client's windows.** There is no per-client or per-application authorization.

| Risk | Detail |
|------|--------|
| No isolation between X clients | Any X application can observe keystrokes (keylogger), inject events, and read screen contents of other applications |
| No permission prompt | Unlike Wayland portals or macOS accessibility permissions, X11 grants XTEST access silently |
| Network X forwarding amplifies risk | If the X display is network-accessible, remote injection is trivial |
| Acceptable only in isolated containers | For CUA, XTEST is safe only when the X server runs inside an isolated container/VM with no other sensitive applications |

**Practical relevance for CUA.** XTEST remains the simplest and most reliable injection mechanism for Linux CUA runtimes that use X11 (especially Xvfb-based headless desktops). The security concerns are mitigated by running Xvfb inside a container where the CUA gateway is the only X client besides the target application.

**xdotool.** The widely-used `xdotool` command-line tool wraps XTEST for scripted automation:

```bash
# Type text
xdotool type "Hello, world"

# Click at coordinates
xdotool mousemove 500 300 click 1

# Press a key combination
xdotool key ctrl+s

# Focus a window by name and click
xdotool search --name "Firefox" windowactivate
xdotool mousemove --window $(xdotool search --name "Firefox") 100 200 click 1
```

---

### libei (Wayland Input Emulation)

**What it is.** `libei` (Emulated Input) is a library developed by Red Hat's Peter Hutterer that provides a standardized way for applications to send emulated input events to Wayland compositors. It was created to solve the problem that Wayland's security model intentionally prevents the X11-style "any client can inject input" pattern. libei 1.0 was released with stable API/ABI guarantees.

**Architecture.** libei has a client-server design:

- **libei** (client side): Used by applications that want to inject input (e.g., a CUA gateway, Synergy/Barrier, virtual keyboards).
- **libeis** (server side): Integrated into the Wayland compositor to receive and validate emulated input events. The compositor can distinguish libei events from real hardware events, enabling fine-grained access control.

**How it works with portals.** The XDG Desktop Portal `RemoteDesktop` interface provides the bridge:

1. Application requests a RemoteDesktop session through the portal D-Bus API.
2. The portal prompts the user for consent (auto-grant behavior is deployment-specific policy, not a universal default).
3. Application calls `org.freedesktop.portal.RemoteDesktop.ConnectToEIS` to get a connection to the compositor's EIS (Emulated Input Server).
4. Application uses libei to create virtual devices and send events over the EIS connection.

```
Application (libei client)
    |
    +-- D-Bus --> XDG Portal (RemoteDesktop)
    |                    |
    |                    v
    |              User consent prompt
    |                    |
    |              ConnectToEIS()
    |                    |
    v                    v
libei <------------> libeis (in compositor)
                         |
                         v
                   Input processing pipeline
```

**Current compositor adoption (2025-2026).**

| Compositor | libei/libeis support |
|------------|---------------------|
| Mutter (GNOME) | Supported since GNOME 45 |
| KWin (KDE) | Under active development |
| wlroots (Sway, etc.) | Tracked in wlroots issue #2378; community patches available |
| Hyprland | Portal-based via xdg-desktop-portal-hyprland |

**Real-world adoption example.** RustDesk (open-source remote desktop) has implemented unprivileged remote access on Wayland through the RemoteDesktop portal and libei, demonstrating the viability of this path for CUA-like systems. Input-Leap (Synergy/Barrier successor) also has a libei backend PR.

**Significance for CUA.** libei is the "correct" way to do input injection on modern Wayland desktops. For CUA gateways targeting Wayland, the recommended path is:

1. Use the RemoteDesktop portal to establish a session (handles permissions).
2. Use libei to inject keyboard and mouse events.
3. Combine with the ScreenCast portal for frame capture.

This is more complex than XTEST but provides proper security mediation and is the only path that is both compositor-portable and sanctioned by the Wayland ecosystem.

---

## Windows Input Injection

### Win32 SendInput

**What it is.** `SendInput` is the canonical Win32 API for synthesizing keyboard and mouse input events. It inserts events into the global input stream, where they are processed by the system as if they came from physical hardware.

**API signature.**

```c
UINT SendInput(
    UINT    cInputs,      // Number of INPUT structures
    LPINPUT pInputs,      // Array of INPUT structures
    int     cbSize         // Size of INPUT structure
);
```

**INPUT structure.**

```c
typedef struct tagINPUT {
    DWORD type;           // INPUT_MOUSE, INPUT_KEYBOARD, or INPUT_HARDWARE
    union {
        MOUSEINPUT    mi;
        KEYBDINPUT    ki;
        HARDWAREINPUT hi;
    } DUMMYUNIONNAME;
} INPUT;

typedef struct tagMOUSEINPUT {
    LONG      dx;          // X coordinate or delta
    LONG      dy;          // Y coordinate or delta
    DWORD     mouseData;   // Wheel delta or X button data
    DWORD     dwFlags;     // MOUSEEVENTF_* flags
    DWORD     time;        // Timestamp (0 = system provides)
    ULONG_PTR dwExtraInfo; // Extra info (app-defined)
} MOUSEINPUT;

typedef struct tagKEYBDINPUT {
    WORD      wVk;         // Virtual-key code
    WORD      wScan;       // Hardware scan code
    DWORD     dwFlags;     // KEYEVENTF_* flags
    DWORD     time;        // Timestamp
    ULONG_PTR dwExtraInfo; // Extra info
} KEYBDINPUT;
```

**Usage example: typing a letter.**

```c
// Type the letter 'A'
INPUT inputs[2] = {};

// Key down
inputs[0].type       = INPUT_KEYBOARD;
inputs[0].ki.wVk     = 'A';
inputs[0].ki.dwFlags = 0;

// Key up
inputs[1].type       = INPUT_KEYBOARD;
inputs[1].ki.wVk     = 'A';
inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;

SendInput(2, inputs, sizeof(INPUT));
```

**Usage example: mouse click at absolute position.**

```c
INPUT inputs[2] = {};

// Move to absolute position (normalized 0-65535)
inputs[0].type      = INPUT_MOUSE;
inputs[0].mi.dx     = (int)(x * 65535.0 / screen_width);
inputs[0].mi.dy     = (int)(y * 65535.0 / screen_height);
inputs[0].mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;

// Left button down + up
inputs[1].type       = INPUT_MOUSE;
inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP;

SendInput(2, inputs, sizeof(INPUT));
```

**Key behaviors.**

- Events are inserted serially into the input stream.
- `SendInput` is atomic: the sequence of events in a single call is guaranteed not to be interleaved with other hardware or software input.
- The function returns the number of events successfully inserted; check against `cInputs` for errors.
- `GetLastError()` is not a reliable UIPI diagnostic by itself; blocked injections can be silent.
- Blocked injections may have ambiguous signaling; require post-action state validation instead of trusting return values alone.

---

### UIPI and Integrity Levels

**User Interface Privilege Isolation (UIPI)** is a security mechanism introduced in Windows Vista that restricts which processes can send window messages and inject input into which other processes, based on their mandatory integrity level.

**Integrity level hierarchy.**

| Level | Label | Typical processes |
|-------|-------|-------------------|
| 0x0000 | Untrusted | Rarely used |
| 0x1000 | Low | Protected Mode IE, sandboxed apps |
| 0x2000 | Medium | Standard user applications |
| 0x3000 | High | Elevated (Run as Administrator) |
| 0x4000 | System | Windows services, kernel objects |

**UIPI rules.**

1. A process can only send window messages (including `SendInput` events) to processes at **equal or lower** integrity levels.
2. A lower-integrity process **cannot** inject input into a higher-integrity process.
3. This prevents a compromised medium-integrity browser from injecting keystrokes into an elevated command prompt.
4. UIPI also blocks `SetWindowsHookEx` across integrity boundaries.

**UIAccess bypass.** Applications can be granted `UIAccess` permission to bypass UIPI restrictions. Requirements:

- The application's manifest must declare `<requestedExecutionLevel level="asInvoker" uiAccess="true"/>`.
- The binary must be digitally signed with a trusted certificate.
- The binary must be installed in a secure location (e.g., `%ProgramFiles%`, `%WinDir%`).
- The Group Policy setting "Only elevate UIAccess applications that are installed in secure locations" must be satisfied.

**Implications for CUA gateway.**

| Scenario | UIPI impact |
|----------|-------------|
| Gateway and target app both at medium IL | SendInput works normally |
| Target app is elevated (high IL) | SendInput from medium-IL gateway is expected to be blocked; error signaling can be ambiguous |
| Gateway inside a VM | UIPI is irrelevant; the gateway controls the entire desktop inside the VM |
| RDP-mediated injection | RDP input bypasses UIPI because it enters through the session's input stack at the system level |

**Best practice.** For CUA, run the target desktop inside a Windows VM. The gateway injects input via RDP protocol or a dedicated agent inside the VM, avoiding UIPI complications entirely. If running on a shared desktop is required, request UIAccess, sign the binary, and install to a secure path.

**Detection of UIPI failures.** Add explicit policy fields for input privilege level (`semantic_only`, `coordinate_allowed`, `raw_device_emulation`) and require the gateway to verify successful injection by checking post-action state changes rather than relying solely on `SendInput` return values.

---

## macOS Input Injection

### Quartz Event Services

**What it is.** Quartz Event Services is the macOS (Core Graphics) framework for creating, posting, and intercepting low-level input events. It provides the ability to create synthetic keyboard and mouse events and inject them into the system's event stream.

**Creating and posting keyboard events.**

```swift
import CoreGraphics

// Create a keyboard event (key down for 'a', virtual keycode 0)
let keyDown = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true)
keyDown?.post(tap: .cghidEventTap)

// Key up
let keyUp = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: false)
keyUp?.post(tap: .cghidEventTap)
```

**Creating and posting mouse events.**

```swift
// Mouse click at (500, 300)
let mouseDown = CGEvent(
    mouseEventSource: nil,
    mouseType: .leftMouseDown,
    mouseCursorPosition: CGPoint(x: 500, y: 300),
    mouseButton: .left
)
mouseDown?.post(tap: .cghidEventTap)

let mouseUp = CGEvent(
    mouseEventSource: nil,
    mouseType: .leftMouseUp,
    mouseCursorPosition: CGPoint(x: 500, y: 300),
    mouseButton: .left
)
mouseUp?.post(tap: .cghidEventTap)
```

**C API equivalents.**

```c
#include <CoreGraphics/CoreGraphics.h>

// Keyboard event
CGEventRef keyEvent = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)0, true);
CGEventPost(kCGHIDEventTap, keyEvent);
CFRelease(keyEvent);

// Mouse event
CGEventRef mouseEvent = CGEventCreateMouseEvent(
    NULL,
    kCGEventLeftMouseDown,
    CGPointMake(500, 300),
    kCGMouseButtonLeft
);
CGEventPost(kCGHIDEventTap, mouseEvent);
CFRelease(mouseEvent);
```

**Event posting locations (tap locations).**

| Tap location | Description |
|-------------|-------------|
| `kCGHIDEventTap` | Events injected at the HID level, before the window server processes them. Most common for input injection. |
| `kCGSessionEventTap` | Events injected at the session level, after HID processing but before application delivery. |
| `kCGAnnotatedSessionEventTap` | Events include annotations from the window server. |

---

### Event Taps

**What they are.** Event taps allow an application to observe and optionally modify the stream of low-level input events flowing through the system. They can be installed at various points in the event pipeline. While primarily useful for monitoring rather than injection, they are important for CUA evidence capture (observing what happened after injection).

**Creating an event tap.**

```swift
import CoreGraphics

// Define the events to observe
let eventMask: CGEventMask = (1 << CGEventType.leftMouseDown.rawValue) |
                              (1 << CGEventType.keyDown.rawValue)

// Create the tap
let tap = CGEvent.tapCreate(
    tap: .cgSessionEventTap,
    place: .headInsertEventTap,
    options: .defaultTap,          // .defaultTap can modify, .listenOnly cannot
    eventsOfInterest: eventMask,
    callback: { proxy, type, event, refcon in
        // Inspect or modify the event
        print("Event type: \(type)")
        return Unmanaged.passRetained(event)
    },
    userInfo: nil
)

// Add to run loop
if let tap = tap {
    let runLoopSource = CFMachPortCreateRunLoopSource(nil, tap, 0)
    CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, .commonModes)
    CGEvent.tapEnable(tap: tap, enable: true)
    CFRunLoopRun()
}
```

**Event tap options.**

| Option | Behavior |
|--------|----------|
| `.defaultTap` | Can observe and modify events (active filter) |
| `.listenOnly` | Can observe but not modify events (passive listener) |

---

### Permission Requirements

**Accessibility permission.** On modern macOS (10.9+), applications that want to create event taps or post synthetic events via Quartz Event Services must be granted Accessibility permission by the user.

**How permissions work.**

1. The application calls `AXIsProcessTrusted()` to check if it has Accessibility permission.
2. If not trusted, `AXIsProcessTrustedWithOptions()` can prompt the user to open System Settings.
3. The user must manually add the application in **System Settings > Privacy & Security > Accessibility**.
4. The permission is stored per-application (by bundle identifier or path).
5. Changes require authentication with an administrator password.

**Recent changes (macOS Sequoia / macOS 15).**

- Apple has tightened restrictions on event taps. Some developers report that `CGEventTapCreate` returns `NULL` even when Accessibility permission is granted, with `AXIsProcessTrusted()` returning `true` but an undocumented `CanFilterEvents` check returning `false`.
- Background helper processes and launch daemons face additional restrictions.
- Sandboxed applications (App Store distribution) **cannot** request Accessibility permission at all.
- Event taps that modify events are more restricted than listen-only taps.

**Implications for CUA.**

| Scenario | Feasibility |
|----------|-------------|
| Unsandboxed app with Accessibility permission | Works, but requires manual user consent per application |
| Sandboxed App Store app | Not possible; cannot request Accessibility |
| CUA inside macOS VM (Apple Virtualization) | The gateway controls the VM; Accessibility can be pre-configured |
| CUA via VNC/ARD to macOS | Input enters via remote desktop protocol; no Accessibility permission needed for the remote client |

**Best practice.** For production CUA on macOS, prefer VM isolation (Apple Virtualization Framework) or remote desktop mediation (VNC/ARD). Direct Quartz Event injection on a shared desktop requires Accessibility permission and is fragile across macOS updates.

---

## Accessibility / Semantic Control Surfaces

Accessibility APIs provide **semantic targeting**: instead of clicking at pixel coordinates (x=500, y=300), a CUA gateway can target "the button named 'Submit' in the dialog titled 'Confirm Purchase'." This dramatically improves:

- **Receipt quality**: Receipts can record *what* was targeted, not just *where*.
- **Robustness**: Semantic targets survive UI layout changes, DPI scaling, and window repositioning.
- **Anti-clickjacking**: Coordinate-only clicks are vulnerable to UI spoofing; semantic matches are harder to spoof.
- **Post-action assertions**: The gateway can verify that the action had the intended effect by re-querying the accessibility tree.

### Windows UI Automation (UIA)

**What it is.** Microsoft UI Automation is a COM-based accessibility framework that exposes UI elements as a tree of automation elements, each with properties, control patterns, and events. It is the successor to MSAA (Microsoft Active Accessibility) and is the standard accessibility API for Windows applications.

**Tree structure.**

```
Desktop (root)
+-- Window: "File Explorer"
|   +-- ToolBar: "Navigation"
|   |   +-- Button: "Back"
|   |   +-- Button: "Forward"
|   |   +-- Button: "Up"
|   +-- TreeView: "Folder Tree"
|   |   +-- TreeItem: "Desktop"
|   |   +-- TreeItem: "Documents"
|   +-- ListView: "File List"
|       +-- ListItem: "report.docx"
|       +-- ListItem: "photo.jpg"
+-- Window: "Chrome"
    +-- Document: "Google Search"
        +-- Edit: "Search box"
        +-- Button: "Google Search"
```

**Core interfaces (COM).**

| Interface | Purpose |
|-----------|---------|
| `IUIAutomation` | Root COM object; creates conditions, tree walkers, retrieves elements. Created via `CoCreateInstance(CLSID_CUIAutomation)` |
| `IUIAutomationElement` | Represents a single UI element with properties (Name, ControlType, BoundingRectangle, IsEnabled, etc.) |
| `IUIAutomationTreeWalker` | Navigates the UI tree (parent, first child, next sibling). Supports different views: Raw, Control, Content |
| `IUIAutomationCondition` | Defines search criteria (property conditions, AND/OR/NOT combinations) |
| `IUIAutomationCacheRequest` | Specifies properties/patterns to cache for batch queries (reduces COM cross-process calls) |

**Control patterns.** Control patterns expose element-specific functionality:

| Pattern | Purpose | Example use |
|---------|---------|-------------|
| `InvokePattern` | Activate a control (click a button) | `element.Invoke()` |
| `ValuePattern` | Get/set the value of a control | `element.SetValue("hello")` for text fields |
| `TextPattern` | Read text content and formatting | `element.DocumentRange.GetText(-1)` |
| `SelectionPattern` | Get/set selected items | Select items in a list box |
| `ScrollPattern` | Scroll a container | `element.Scroll(horizontal, vertical)` |
| `TogglePattern` | Toggle a checkbox | `element.Toggle()` |
| `ExpandCollapsePattern` | Expand/collapse tree nodes, menus | `element.Expand()` |
| `WindowPattern` | Minimize, maximize, close windows | `element.Close()` |
| `TransformPattern` | Move, resize, rotate elements | Repositioning windows |
| `GridPattern` / `TablePattern` | Navigate grid/table structures | Read cell values |

**Usage example (C#).**

```csharp
using System.Windows.Automation;

// Find the "Submit" button by name
AutomationElement root = AutomationElement.RootElement;
AutomationElement button = root.FindFirst(
    TreeScope.Descendants,
    new PropertyCondition(AutomationElement.NameProperty, "Submit")
);

if (button != null) {
    // Get bounding rect for receipt evidence
    Rect bounds = button.Current.BoundingRectangle;
    string controlType = button.Current.ControlType.ProgrammaticName;

    // Invoke the button semantically (no coordinate injection needed)
    InvokePattern invoke = (InvokePattern)button.GetCurrentPattern(
        InvokePattern.Pattern
    );
    invoke.Invoke();
}
```

**Usage example (C++ COM).**

```cpp
#include <UIAutomation.h>

IUIAutomation *pAutomation = nullptr;
CoCreateInstance(CLSID_CUIAutomation, nullptr,
    CLSCTX_INPROC_SERVER, IID_IUIAutomation,
    (void**)&pAutomation);

IUIAutomationElement *pRoot = nullptr;
pAutomation->GetRootElement(&pRoot);

// Create condition: Name == "Submit"
VARIANT varName;
varName.vt = VT_BSTR;
varName.bstrVal = SysAllocString(L"Submit");

IUIAutomationCondition *pCondition = nullptr;
pAutomation->CreatePropertyCondition(UIA_NamePropertyId,
    varName, &pCondition);

IUIAutomationElement *pButton = nullptr;
pRoot->FindFirst(TreeScope_Descendants, pCondition, &pButton);

if (pButton) {
    IUIAutomationInvokePattern *pInvoke = nullptr;
    pButton->GetCurrentPattern(UIA_InvokePatternId,
        (IUnknown**)&pInvoke);
    if (pInvoke) {
        pInvoke->Invoke();
        pInvoke->Release();
    }
    pButton->Release();
}
```

**Value for CUA receipts.** UIA enables receipts that contain:

- Element role and name (e.g., "Button: Submit")
- Control type (programmatic name)
- Bounding rectangle (for cross-referencing with screenshot evidence)
- Parent window title and application identity
- Element state (enabled, focused, offscreen, etc.)
- Automation ID (developer-assigned stable identifier)

---

### macOS AXUIElement

**What it is.** `AXUIElement` is the core accessibility object type in the macOS Accessibility API. Every UI element on screen (windows, buttons, text fields, menus) is represented as an `AXUIElement` with attributes, actions, and notification capabilities.

**Core operations.**

| Function | Purpose |
|----------|---------|
| `AXUIElementCreateSystemWide()` | Get a reference to the system-wide accessibility element (root of all applications) |
| `AXUIElementCreateApplication(pid)` | Get the accessibility element for a specific application by PID |
| `AXUIElementCopyAttributeValue(element, attribute, &value)` | Read an attribute (e.g., title, role, children, position) |
| `AXUIElementCopyAttributeNames(element, &names)` | List available attributes for an element |
| `AXUIElementSetAttributeValue(element, attribute, value)` | Set an attribute (e.g., set text field value, move window) |
| `AXUIElementPerformAction(element, action)` | Perform an action (e.g., `kAXPressAction`, `kAXShowMenuAction`) |
| `AXUIElementCopyActionNames(element, &names)` | List available actions for an element |
| `AXUIElementGetPid(element, &pid)` | Get the PID of the application owning an element |

**Common attributes.**

| Attribute constant | Description |
|--------------------|-------------|
| `kAXRoleAttribute` | Element type (e.g., "AXButton", "AXTextField", "AXWindow") |
| `kAXRoleDescriptionAttribute` | Human-readable role description |
| `kAXTitleAttribute` | Element title (e.g., button label) |
| `kAXValueAttribute` | Current value (text field content, slider value) |
| `kAXPositionAttribute` | Screen position (CGPoint) |
| `kAXSizeAttribute` | Element size (CGSize) |
| `kAXChildrenAttribute` | Child elements (CFArray of AXUIElement) |
| `kAXParentAttribute` | Parent element |
| `kAXFocusedAttribute` | Whether element has keyboard focus |
| `kAXEnabledAttribute` | Whether element is enabled for interaction |
| `kAXSubroleAttribute` | More specific role (e.g., "AXCloseButton", "AXSearchField") |
| `kAXDescriptionAttribute` | Accessibility description |
| `kAXIdentifierAttribute` | Developer-assigned identifier |

**Error codes from AXUIElementCopyAttributeValue.**

| Error | Meaning |
|-------|---------|
| `kAXErrorSuccess` | Attribute value retrieved successfully |
| `kAXErrorAttributeUnsupported` | The element does not support the specified attribute |
| `kAXErrorNoValue` | The attribute exists but has no value |
| `kAXErrorIllegalArgument` | Invalid argument passed |
| `kAXErrorInvalidUIElement` | The element no longer exists (window closed, etc.) |
| `kAXErrorCannotComplete` | Communication with the application failed |
| `kAXErrorNotImplemented` | The attribute is not implemented by the application |

**Observing UI changes.** The `AXObserver` API allows monitoring for UI changes:

```swift
import ApplicationServices

// Create observer for a specific application
var observer: AXObserver?
let callback: AXObserverCallback = { observer, element, notification, refcon in
    var role: AnyObject?
    AXUIElementCopyAttributeValue(element, kAXRoleAttribute as CFString, &role)
    print("Notification: \(notification), Role: \(role ?? "unknown")")
}

AXObserverCreate(pid, callback, &observer)

// Register for specific notifications
let element = AXUIElementCreateApplication(pid)
AXObserverAddNotification(observer!, element,
    kAXFocusedUIElementChangedNotification as CFString, nil)
AXObserverAddNotification(observer!, element,
    kAXValueChangedNotification as CFString, nil)
AXObserverAddNotification(observer!, element,
    kAXWindowCreatedNotification as CFString, nil)

// Add to run loop
CFRunLoopAddSource(
    CFRunLoopGetCurrent(),
    AXObserverGetRunLoopSource(observer!),
    .defaultMode
)
```

**Key notifications.**

| Notification | Fires when |
|-------------|------------|
| `kAXFocusedUIElementChangedNotification` | Focus moves to a different element |
| `kAXValueChangedNotification` | Element value changes (text input, slider) |
| `kAXUIElementDestroyedNotification` | Element is destroyed |
| `kAXWindowCreatedNotification` | New window appears |
| `kAXWindowMovedNotification` | Window is repositioned |
| `kAXWindowResizedNotification` | Window is resized |
| `kAXSelectedTextChangedNotification` | Text selection changes |
| `kAXMenuOpenedNotification` | Menu opens |

**Permission requirement.** Like Quartz Event Services, AXUIElement APIs require Accessibility permission (System Settings > Privacy & Security > Accessibility). The application must be listed and enabled.

**Swift wrapper: AXorcist.** A recent (2025) open-source Swift wrapper called AXorcist provides chainable, fuzzy-matched queries for macOS accessibility elements:

```swift
// Find and click a button named "Submit" in any window
let result = AXorcist.query()
    .role(.button)
    .name("Submit")
    .first()
    .press()
```

This pattern is well-suited for CUA gateways that need semantic targeting on macOS.

---

### Linux AT-SPI

**What it is.** AT-SPI (Assistive Technology Service Provider Interface) is the Linux/Unix accessibility framework, providing a D-Bus-based protocol for communication between applications, assistive technologies (screen readers, magnifiers), and the desktop environment. It is the Linux equivalent of Windows UIA and macOS AXUIElement.

**Architecture.**

```
Application (GTK/Qt/Electron/Firefox)
    |
    +-- ATK/AT-SPI bridge (exports UI tree over D-Bus)
    |
    v
D-Bus session bus
    |
    +-- registryd (registry daemon, tracks accessible apps)
    |
    v
Screen reader / CUA gateway (consumes the tree)
```

**Core components.**

| Component | Role |
|-----------|------|
| `at-spi2-core` | Core library and registry daemon; provides D-Bus interfaces for accessible objects |
| `at-spi2-atk` | Bridge between ATK (GNOME accessibility toolkit) and AT-SPI D-Bus interfaces |
| `pyatspi2` | Python bindings for consuming the AT-SPI tree (used by Orca screen reader) |
| `registryd` | Daemon that tracks accessible applications and mediates discovery |

**D-Bus interfaces.**

| Interface | Purpose |
|-----------|---------|
| `org.a11y.atspi.Accessible` | Core interface: Name, Role, Description, ChildCount, GetChildAtIndex, GetRelationSet |
| `org.a11y.atspi.Action` | DoAction (e.g., "click", "activate"), GetActionCount, GetActionName |
| `org.a11y.atspi.Text` | GetText, GetCaretOffset, GetCharacterAtOffset, GetSelection |
| `org.a11y.atspi.EditableText` | SetTextContents, InsertText, DeleteText, SetCaretOffset |
| `org.a11y.atspi.Value` | CurrentValue, MinimumValue, MaximumValue, SetCurrentValue |
| `org.a11y.atspi.Component` | GetExtents, GetPosition, GetSize, Contains, GetAccessibleAtPoint |
| `org.a11y.atspi.Selection` | GetSelectedChild, SelectChild, DeselectChild, SelectAll |
| `org.a11y.atspi.Document` | GetAttributeValue (e.g., URL, mime-type) for document elements |

**Python example using pyatspi2.**

```python
import pyatspi

# Get the desktop (root) object
desktop = pyatspi.Registry.getDesktop(0)

# Iterate over applications
for app in desktop:
    print(f"Application: {app.name}")
    for window in app:
        print(f"  Window: {window.name}, Role: {window.getRoleName()}")

        # Find a button by name
        def find_button(node, name):
            if node.getRoleName() == "push button" and node.name == name:
                return node
            for i in range(node.childCount):
                result = find_button(node.getChildAtIndex(i), name)
                if result:
                    return result
            return None

        btn = find_button(window, "Submit")
        if btn:
            # Get bounding box for receipt
            extent = btn.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)
            print(f"  Found button at ({extent.x}, {extent.y})")

            # Perform the action
            action_iface = btn.queryAction()
            if action_iface:
                for i in range(action_iface.nActions):
                    if action_iface.getName(i) == "click":
                        action_iface.doAction(i)
```

**Toolkit support.**

| Toolkit | AT-SPI support |
|---------|---------------|
| GTK 3/4 | Full support via ATK bridge (built-in) |
| Qt 5/6 | Full support via Qt Accessibility module (QAccessible) |
| Electron/Chromium | Supported (enable with `--force-renderer-accessibility`) |
| Firefox | Full support |
| Java/Swing | Supported via Java Access Bridge |
| LibreOffice | Full support |
| Flutter (Linux) | Partial support via ATK bridge |

**Limitations for CUA.**

| Limitation | Detail |
|-----------|--------|
| Inconsistent quality | AT-SPI tree quality varies significantly by application; some expose rich trees, others are minimal or broken |
| D-Bus latency | D-Bus transport adds latency compared to in-process APIs (UIA, AXUIElement); tree traversal can be slow for large UIs |
| Wayland gaps | Screen readers like Orca work on Wayland but may have gaps on some compositors |
| Runtime requirements | `at-spi2-registryd` must be running; `DBUS_SESSION_BUS_ADDRESS` must be set correctly in CUA runtime |
| Chromium opt-in | Chromium/Electron apps require `--force-renderer-accessibility` flag to expose the full tree |

---

## Wayland-Specific Mechanisms

### XDG Desktop Portal RemoteDesktop

**What it is.** The XDG Desktop Portal `RemoteDesktop` interface is a D-Bus API that provides a standardized, permission-mediated way to create remote desktop sessions on Wayland (and optionally X11) desktops. It is the "official" mechanism for input injection and screen capture on modern Linux desktops that use Wayland. The current specification is at version 2.

**D-Bus interface.** The portal is accessed at:
- Bus name: `org.freedesktop.portal.Desktop`
- Object path: `/org/freedesktop/portal/desktop`
- Interface: `org.freedesktop.portal.RemoteDesktop`

**Session creation flow.**

```
1. CreateSession(options) -> session_handle
   Options include session type, what to share, etc.

2. SelectDevices(session_handle, options)
   Specify device types to request (bitmask):
   - KEYBOARD (1)
   - POINTER  (2)
   - TOUCHSCREEN (4)
   Default: all device types.

3. Start(session_handle, parent_window, options) -> streams
   User consent prompt appears.
   Returns PipeWire stream nodes for screen content.

4. ConnectToEIS(session_handle, options) -> fd
   Get a file descriptor for the EIS (Emulated Input Server)
   connection in the compositor. Use with libei.
```

**Device types (bitmask).**

| Value | Device type | Description |
|-------|-------------|-------------|
| 1 | `KEYBOARD` | Virtual keyboard device for key events |
| 2 | `POINTER` | Virtual pointer device for mouse events |
| 4 | `TOUCHSCREEN` | Virtual touchscreen for touch events |

**Direct input injection methods (no libei needed).**

The portal also provides D-Bus methods for input injection:

| Method | Parameters | Description |
|--------|-----------|-------------|
| `NotifyKeyboardKeycode` | session, options, keycode, state | Send a keyboard event by kernel keycode |
| `NotifyKeyboardKeysym` | session, options, keysym, state | Send a keyboard event by X keysym |
| `NotifyPointerMotion` | session, options, dx, dy | Relative pointer movement |
| `NotifyPointerMotionAbsolute` | session, options, stream, x, y | Absolute pointer positioning |
| `NotifyPointerButton` | session, options, button, state | Mouse button press/release |
| `NotifyPointerAxis` | session, options, dx, dy | Scroll events |
| `NotifyTouchDown` | session, options, stream, slot, x, y | Touch begin |
| `NotifyTouchMotion` | session, options, stream, slot, x, y | Touch move |
| `NotifyTouchUp` | session, options, slot | Touch end |

**libportal convenience API.** The `libportal` library provides C bindings that simplify portal interaction:

```c
#include <libportal/portal.h>
#include <libportal/remote-desktop.h>

XdpPortal *portal = xdp_portal_new();

// Create session with keyboard and pointer
xdp_portal_create_remote_desktop_session(
    portal,
    XDP_DEVICE_KEYBOARD | XDP_DEVICE_POINTER,
    XDP_OUTPUT_NONE,  // no screen sharing needed for input-only
    XDP_REMOTE_DESKTOP_FLAG_NONE,
    NULL,  // cursor mode
    NULL,  // cancellable
    session_created_callback,
    user_data
);
```

**Portal implementations by compositor.**

| Desktop | Portal implementation | Notes |
|---------|---------------------|-------|
| GNOME | `xdg-desktop-portal-gnome` | Full RemoteDesktop + ScreenCast support |
| KDE | `xdg-desktop-portal-kde` | Full support |
| Sway/wlroots | `xdg-desktop-portal-wlr` | ScreenCast supported; RemoteDesktop limited |
| Hyprland | `xdg-desktop-portal-hyprland` | RemoteDesktop with libei support |
| Cosmic (System76) | `xdg-desktop-portal-cosmic` | Under development |

---

### KDE Fake Input Protocol

**What it is.** `org_kde_kwin_fake_input` is a Wayland protocol extension specific to KDE's KWin compositor. It allows clients to request that the compositor process synthetic input events (keyboard and mouse).

**Protocol specification (simplified).**

```xml
<interface name="org_kde_kwin_fake_input" version="4">
  <request name="authenticate">
    <arg name="application" type="string"/>
    <arg name="reason" type="string"/>
  </request>
  <request name="pointer_motion">
    <arg name="delta_x" type="fixed"/>
    <arg name="delta_y" type="fixed"/>
  </request>
  <request name="button">
    <arg name="button" type="uint"/>
    <arg name="state" type="uint"/>
  </request>
  <request name="axis">
    <arg name="axis" type="uint"/>
    <arg name="value" type="fixed"/>
  </request>
  <request name="keyboard_key">
    <arg name="key" type="uint"/>
    <arg name="state" type="uint"/>
  </request>
  <request name="pointer_motion_absolute">
    <arg name="x" type="fixed"/>
    <arg name="y" type="fixed"/>
  </request>
  <request name="touch_down">...</request>
  <request name="touch_motion">...</request>
  <request name="touch_up">...</request>
  <request name="touch_cancel">...</request>
  <request name="touch_frame">...</request>
</interface>
```

**Security warnings (from the protocol spec).**

The protocol documentation contains explicit security warnings:

> "This is a desktop environment implementation detail. Regular clients must not use this interface."
>
> "A compositor should not trust the input received from this interface."
>
> "Clients should not expect that the compositor honors the requests from this interface."

**Authentication.** The `authenticate` request allows the client to declare its identity and reason for needing fake input. KWin currently does not enforce a strict permission model for this protocol, but reserves the right to reject requests in future versions.

**Recommendation for CUA.** Do not build CUA gateway logic around `org_kde_kwin_fake_input`:

- **Not portable**: Only works on KWin.
- **Not trusted by design**: The compositor explicitly warns against trusting this input.
- **Superseded by libei**: The libei/portal path is more standardized and future-proof, even on KDE.
- **No permission mediation**: Unlike portals, there is no user consent flow.

Use the XDG RemoteDesktop portal instead.

---

### Wayland Security Model Deep Dive

**Why global input injection is intentionally impossible on Wayland.**

The Wayland protocol was designed from the ground up to address the fundamental security weaknesses of X11. In X11, any client connected to the X server has implicit access to:

1. **All keyboard input** from all applications (enabling keyloggers).
2. **All screen content** from all applications (enabling screen scrapers).
3. **The input stream** of all applications (enabling event injection via XTEST).

Wayland eliminates all three capabilities by design:

| X11 behavior | Wayland design |
|-------------|----------------|
| Any client can read all keyboard input | Only the focused surface receives input events |
| Any client can capture any screen content | Clients can only access their own surface buffers |
| Any client can inject synthetic input via XTEST | No protocol-level mechanism for input injection |
| Clients share a global coordinate space | Each surface has its own local coordinate space |
| No application isolation | Full client isolation enforced by compositor |

**The security rationale.** The Wayland developers made a deliberate architectural choice:

> Unlike X, the Wayland input stack doesn't allow applications to snoop on the input of other programs (preserving **confidentiality**), to generate input events that appear to come from the user (preserving **input integrity**), or to capture all the input events to the exclusion of the user's application (preserving **availability**).

This aligns with GNOME 50's move to Wayland-only, which explicitly cites enhanced security and isolation as motivating factors.

**How portals solve the problem.**

Portals provide a controlled "escape hatch" for legitimate use cases:

```
Application
    |
    +-- D-Bus request to portal
    |
    v
XDG Desktop Portal daemon
    |
    +-- Policy check (user consent, sandboxing rules)
    |
    v
Compositor / PipeWire
    |
    +-- Scoped access (specific screen, specific device types)
    |
    v
Result (screen content stream, input injection capability)
```

**Key security properties of the portal approach.**

| Property | Detail |
|----------|--------|
| User mediation | The user must explicitly grant permission for screen capture and input injection |
| Scoping | Permissions can be scoped to specific screens, windows, or device types |
| Revocability | Permissions can be revoked at any time by closing the session |
| Audit trail | The portal daemon and compositor can log access |
| Sandbox alignment | Portals integrate with Flatpak/Snap sandboxing, providing fine-grained capability grants |
| Session-based | Access is tied to a session that has a defined lifecycle |

**Portal security tradeoffs.** While portals are a significant improvement, they are not perfect:

- The ScreenCast portal opens access to screen content, which is a significant capability.
- The RemoteDesktop portal grants input injection, which combined with screen capture gives full desktop control.
- The user consent prompt is a single decision that grants broad access for the session duration.
- In headless/kiosk scenarios, consent may be auto-granted, reducing the security benefit.

**Implications for CUA gateway design.**

| Scenario | Approach |
|----------|----------|
| CUA targeting a Wayland desktop | Must use RemoteDesktop + ScreenCast portals; cannot bypass |
| CUA inside a headless Wayland container | Compositor can auto-grant portal permissions (no user prompt) |
| CUA inside an X11 container (Xvfb) | XTEST works; Wayland restrictions don't apply; simpler but less "modern" |
| CUA via RDP to a Wayland desktop | Input enters via compositor's RDP backend; portal may not be needed |
| CUA using Weston RDP backend | Weston headless + RDP; interact only via RDP; no portal needed |

**The wlr-virtual-pointer / wlr-virtual-keyboard protocols.** Some wlroots-based compositors expose non-standard protocols for virtual input:

- `zwlr_virtual_pointer_v1`: Create virtual pointer devices.
- `zwp_virtual_keyboard_v1`: Create virtual keyboards.

These are simpler than the portal path but:
- Are compositor-specific (wlroots family only).
- Don't provide permission mediation.
- Are primarily intended for input method editors and virtual keyboards, not external automation.

The `wtype` command-line tool uses `zwp_virtual_keyboard_v1` for Wayland-native text input.

---

## Cross-Platform Abstractions

### PyAutoGUI

**What it is.** PyAutoGUI is a Python module for cross-platform GUI automation. It provides a simple, high-level API for controlling the mouse and keyboard on Windows, macOS, and Linux.

**Core API.**

```python
import pyautogui

# Mouse operations
pyautogui.moveTo(500, 300)              # Move to absolute position
pyautogui.moveRel(100, 0)               # Move relative
pyautogui.click(500, 300)               # Click at position
pyautogui.click(clicks=2)               # Double-click at current position
pyautogui.rightClick(500, 300)           # Right-click
pyautogui.scroll(3)                      # Scroll up 3 "clicks"
pyautogui.drag(100, 0, duration=0.5)     # Drag 100px right

# Keyboard operations
pyautogui.typewrite('Hello', interval=0.05)  # Type text with delay
pyautogui.hotkey('ctrl', 'c')                # Key combination
pyautogui.press('enter')                      # Single key press
pyautogui.keyDown('shift')                    # Hold key
pyautogui.keyUp('shift')                      # Release key

# Screen operations
screenshot = pyautogui.screenshot()             # Full screenshot
location = pyautogui.locateOnScreen('btn.png')  # Image matching
```

**Platform backends.**

| Platform | Injection backend | Screenshot backend |
|----------|-------------------|-------------------|
| Windows | Win32 `SendInput` | Pillow/win32api |
| macOS | Quartz Event Services | screencapture |
| Linux (X11) | XTEST | scrot/Pillow/Xlib |
| Linux (Wayland) | **Not supported** | Partially broken |

**Limitations for production CUA.**

| Limitation | Detail |
|-----------|--------|
| No semantic targeting | Works exclusively with pixel coordinates and image matching; no DOM/accessibility integration |
| Multi-monitor issues | Only reliably works on the primary monitor |
| No Wayland support | Relies on XTEST (X11) on Linux; does not work on Wayland compositors |
| No audit primitives | No built-in logging, receipts, or evidence capture |
| Race conditions | `typewrite()` sends characters sequentially with configurable delays; no guarantee the target app has processed previous input |
| Screenshot matching is brittle | `locateOnScreen()` is sensitive to DPI, theme changes, font rendering, and antialiasing |
| No event confirmation | No way to verify that injected events were processed by the intended application |
| Python GIL | Single-threaded execution limits throughput for high-frequency input |
| No keylogging | Cannot detect if a key is currently pressed down |

**When to use PyAutoGUI in CUA context.**

- Quick prototyping of CUA interaction patterns.
- Testing CUA receipt pipelines against known UI states.
- Educational demonstrations.

**Not appropriate for:**

- Production CUA gateways (no security, no audit, no semantic targeting).
- High-assurance systems (no attestation, no receipts).
- Wayland targets.

---

### Other Cross-Platform Libraries

| Library | Language | Platforms | Injection Method | Semantic Targeting | Wayland | Maintenance Status |
|---------|----------|-----------|-----------------|-------------------|---------|-------------------|
| **pynput** | Python | Win/Mac/Linux(X11) | SendInput / Quartz / XTEST | No | No | Active |
| **robotjs** | Node.js (native) | Win/Mac/Linux(X11) | Native per-platform | No | No | Low maintenance |
| **enigo** | Rust | Win/Mac/Linux(X11) | Native per-platform | No | No | Active |
| **AutoIt** | AutoIt/COM | Windows only | SendInput + UIA | Yes (Windows) | N/A | Active |
| **xdotool** | C (CLI) | Linux (X11 only) | XTEST | No | No | Mature/stable |
| **ydotool** | C (CLI) | Linux (uinput) | uinput | No | Yes (kernel-level) | Active |
| **wtype** | C (CLI) | Linux (Wayland) | `zwp_virtual_keyboard_v1` | No | Yes (wlroots) | Active |
| **dotool** | Go (CLI) | Linux (uinput/libei) | uinput or libei | No | Yes | Active |
| **AXorcist** | Swift | macOS only | AXUIElement | Yes (macOS) | N/A | New (2025) |

---

## Comparison Matrix

### Input Injection Methods

| Method | Platform | Injection Level | Permission Model | Wayland | Semantic Targeting | Latency | CUA Suitability |
|--------|----------|----------------|-----------------|---------|-------------------|---------|-----------------|
| **uinput** | Linux | Kernel (evdev) | File perms on `/dev/uinput` | Yes (kernel-level) | None | <1ms | Good (in isolated runtime) |
| **libevdev** | Linux | Kernel (evdev) | Same as uinput | Yes | None | <1ms | Good (safer API) |
| **XTEST** | Linux (X11) | X server | None (any X client) | No | None | ~1ms | Good (in Xvfb container) |
| **libei** | Linux (Wayland) | Compositor | Portal-mediated | Yes (designed for it) | None | 1-5ms | Best for Wayland |
| **Portal RD D-Bus** | Linux (Wayland) | D-Bus + Compositor | Portal-mediated | Yes | None | 5-10ms | Best for portability |
| **KDE fake input** | Linux (KDE) | Compositor | Untrusted by design | KWin only | None | ~1ms | Poor (not portable) |
| **SendInput** | Windows | User-mode input queue | UIPI integrity levels | N/A | None | <1ms | Good (in VM) |
| **Quartz Events** | macOS | HID/session | Accessibility permission | N/A | None | <1ms | Good (in VM) |
| **PyAutoGUI** | Cross-platform | Wraps per-platform | Per-platform | No | None | 10-50ms | Prototype only |

### Accessibility / Semantic Control APIs

| API | Platform | Transport | Tree Model | Key Patterns/Actions | Permission Model | CUA Receipt Value |
|-----|----------|-----------|-----------|---------------------|-----------------|-------------------|
| **Windows UIA** | Windows | COM (in-process/cross-process) | Tree rooted at Desktop | Invoke, Value, Text, Toggle, Scroll, ExpandCollapse, Window | OS-governed; no special perm for reading | High |
| **macOS AXUIElement** | macOS | Mach IPC | Per-app element tree | Press, Increment, ShowMenu, Pick, Cancel, Confirm | Accessibility perm required | High |
| **Linux AT-SPI** | Linux | D-Bus session bus | D-Bus tree via registryd | DoAction, SetValue, InsertText, SetCaret | No special perm | Medium-High (varies) |

### Combined Assessment for CUA Gateway

| Platform | Recommended Injection | Recommended Semantic API | Recommended Deployment |
|----------|----------------------|-------------------------|----------------------|
| **Linux (Xvfb)** | XTEST (simplest) or uinput | AT-SPI (if apps support it) | Container with Xvfb; gateway is sole X client |
| **Linux (Wayland)** | RemoteDesktop portal + libei | AT-SPI | Headless compositor (Weston RDP, GNOME Remote Desktop) |
| **Windows** | SendInput (inside VM) or RDP | UIA (rich semantic targeting) | Windows VM accessed via RDP |
| **macOS** | Quartz Events (inside VM) or VNC | AXUIElement | macOS VM (Apple Virtualization) via VNC |
| **Browser-first** | CDP/Playwright (not OS-level) | CDP Accessibility domain | Browser in container; no OS injection needed |

---

## Implications for CUA Gateway Design

### Architecture Recommendations

1. **Prefer remote desktop protocol mediation over direct OS injection.** When the CUA gateway communicates with the target desktop via RDP, VNC, or WebRTC, input injection happens through the remote desktop protocol's input channel. This:
   - Avoids platform-specific injection API complexity.
   - Avoids permission issues (UIPI, macOS Accessibility).
   - Works consistently across platforms.
   - Is naturally isolated (the gateway never runs on the target desktop).

2. **Layer semantic targeting on top of coordinate injection.** The gateway should:
   - Query the accessibility tree (UIA, AXUIElement, AT-SPI) to resolve semantic targets to coordinates.
   - Inject input at the resolved coordinates (via the chosen injection mechanism).
   - Include both the semantic target and the coordinates in the receipt.
   - Verify post-action accessibility state matches expectations.
   - Require post-action assertions for privileged actions (URL/window title/text checks) to prevent blind injection drift.

3. **For the MVP, start with Xvfb + XTEST + AT-SPI on Linux.** This combination:
   - Is the simplest to set up (one container, no compositor complexity).
   - Provides reliable injection (XTEST is battle-tested).
   - Supports semantic targeting (AT-SPI for GTK/Qt/Electron apps).
   - Runs headlessly without GPU.
   - Can be captured via x11grab (FFmpeg) or VNC streaming.

4. **Plan for Wayland transition.** As GNOME and KDE move to Wayland-only, the gateway must support:
   - RemoteDesktop portal + libei for input.
   - ScreenCast portal + PipeWire for capture.
   - OR: Use a headless Wayland compositor (Weston RDP backend) where the gateway connects via RDP, sidestepping the portal flow entirely.

5. **Never expose uinput or XTEST on shared desktops.** These mechanisms provide no isolation. A compromised CUA agent with uinput access can inject arbitrary input into any application on the system. Always confine these mechanisms inside isolated runtimes (containers, VMs).

6. **Add explicit policy fields for input privilege level.** The policy engine should support:
   - `semantic_only` -- only allow actions targeted by accessibility role/name.
   - `coordinate_allowed` -- allow coordinate-based injection (with semantic validation if available).
   - `raw_device_emulation` -- allow uinput/low-level injection (highest privilege, requires strongest isolation).

### Receipt Evidence from Input Injection

For each injected action, the receipt should capture:

| Field | Source | Purpose |
|-------|--------|---------|
| `action.kind` | Gateway | What type of action (click, type, key_chord) |
| `action.pointer.{x,y}` | Gateway | Pixel coordinates of injection |
| `action.target_hint.role` | Accessibility API | Semantic role of target element |
| `action.target_hint.name` | Accessibility API | Name/label of target element |
| `action.target_hint.bounds` | Accessibility API | Bounding rectangle for cross-reference |
| `action.target_hint.window_title` | Accessibility API | Window containing the target |
| `action.target_hint.app_id` | Accessibility API | Application identity |
| `evidence.pre.frame_hash` | Screen capture | Hash of screen before action |
| `evidence.post.frame_hash` | Screen capture | Hash of screen after action |
| `evidence.ui_context.ax_tree_hash` | Accessibility API | Hash of accessibility tree snapshot |
| `injection.method` | Gateway | Which injection mechanism was used |
| `injection.privilege_level` | Policy engine | What level of injection was authorized |

### Abuse Prevention

- **Rate limits**: Cap click/keystroke rate to prevent runaway automation loops.
- **Input flood detection**: Monitor for anomalous injection frequency and auto-pause.
- **UIPI mismatch handling**: Detect and report when UIPI blocks injection; return deterministic failure reason.
- **Silent failure detection**: Verify post-action state changes rather than relying on injection API return values.

---

## References

### Linux uinput / libevdev
- [Linux Kernel uinput documentation](https://docs.kernel.org/input/uinput.html)
- [libevdev uinput device creation API](https://www.freedesktop.org/software/libevdev/doc/latest/group__uinput.html)
- [python-libevdev documentation](https://python-libevdev.readthedocs.io/)
- [libevdev source (GitHub)](https://github.com/whot/libevdev)

### XTEST
- [XTEST Extension Protocol specification](https://www.x.org/releases/X11R7.7/doc/xextproto/xtest.html)
- [XTestFakeKeyEvent man page](https://linux.die.net/man/3/xtestfakekeyevent)

### libei
- [libei 1.0 release (Phoronix)](https://www.phoronix.com/news/libei-1.0-Emulated-Input)
- [EI Protocol documentation](https://libinput.pages.freedesktop.org/libei/)
- [RFC: libei - emulated input in Wayland compositors](https://lists.freedesktop.org/archives/wayland-devel/2020-August/041571.html)
- [RustDesk libei discussion](https://github.com/rustdesk/rustdesk/discussions/4515)
- [Input-Leap libei backend PR](https://github.com/input-leap/input-leap/pull/1594)

### Win32 SendInput / UIPI
- [SendInput function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput)
- [User Interface Privilege Isolation (Wikipedia)](https://en.wikipedia.org/wiki/User_Interface_Privilege_Isolation)
- [UIPI deep dive (GitHub)](https://github.com/Chaoses-Ib/Windows/blob/main/Kernel/Security/UIPI.md)
- [SendInput UIPI failure (Microsoft Learn)](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/b68a77e7-cd00-48d0-90a6-d6a4a46a95aa)

### macOS Quartz / Accessibility
- [Quartz Event Services (Apple Developer)](https://developer.apple.com/documentation/coregraphics/quartz-event-services)
- [CGEventCreateKeyboardEvent (Apple Developer)](https://developer.apple.com/documentation/coregraphics/1456564-cgeventcreatekeyboardevent)
- [CGEventCreateMouseEvent (Apple Developer)](https://developer.apple.com/documentation/coregraphics/1454356-cgeventcreatemouseevent)
- [AXUIElement (Apple Developer)](https://developer.apple.com/documentation/applicationservices/axuielement)
- [AXUIElementCopyAttributeValue (Apple Developer)](https://developer.apple.com/documentation/applicationservices/1462085-axuielementcopyattributevalue)
- [AXorcist - Swift macOS Accessibility wrapper (GitHub)](https://github.com/steipete/AXorcist)
- [Parsing macOS application UI (MacPaw Research)](https://research.macpaw.com/publications/how-to-parse-macos-app-ui)

### Windows UI Automation
- [UI Automation Control Patterns Overview (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/framework/ui-automation/ui-automation-control-patterns-overview)
- [UI Automation Tree Overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-treeoverview)
- [Control Pattern Identifiers (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-controlpattern-ids)

### Linux AT-SPI
- [AT-SPI2 (freedesktop.org)](https://www.freedesktop.org/wiki/Accessibility/AT-SPI2/)
- [AT-SPI on D-Bus (Linux Foundation Wiki)](https://wiki.linuxfoundation.org/accessibility/atk/at-spi/at-spi_on_d-bus)
- [Ubuntu Desktop Accessibility Stack](https://documentation.ubuntu.com/desktop/en/latest/explanation/accessibility-stack/)
- [at-spi2-core (GNOME GitLab)](https://github.com/GNOME/at-spi2-core)
- [Enhancing screen-reader functionality in modern GNOME (LWN.net)](https://lwn.net/Articles/1025127/)

### Wayland / Portals
- [XDG Desktop Portal RemoteDesktop documentation](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)
- [XDG Desktop Portal (ArchWiki)](https://wiki.archlinux.org/title/XDG_Desktop_Portal)
- [libportal API reference](https://libportal.org/libportal.html)
- [KDE fake input protocol (Wayland Explorer)](https://wayland.app/protocols/kde-fake-input)
- [Wayland security context protocol](https://wayland.app/protocols/security-context-v1)
- [GNOME 50: Wayland-Only Enhanced Security](https://linuxsecurity.com/news/desktop-security/gnome-50-wayland-linux-security)
- [Wayland security model (LWN.net)](https://lwn.net/Articles/589147/)
- [Exploring Wayland fragmentation (xdotool adventure)](https://www.semicomplete.com/blog/xdotool-and-exploring-wayland-fragmentation/)

### Cross-Platform
- [PyAutoGUI documentation](https://pyautogui.readthedocs.io/)
- [PyAutoGUI (GitHub)](https://github.com/asweigart/pyautogui)
- [PyAutoGUI (PyPI)](https://pypi.org/project/PyAutoGUI/)
