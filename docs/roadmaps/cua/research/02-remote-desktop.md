# Remote Desktop & Virtual Display Technologies

> Research document for the Clawdstrike CUA Gateway project.
> Covers remote desktop protocols, virtual display servers, streaming technologies,
> and their roles in providing controlled desktop runtimes for computer-use agents.

---

## Table of Contents

1. [Overview](#overview)
2. [Apache Guacamole](#apache-guacamole)
   - [Architecture](#guacamole-architecture)
   - [Guacamole Protocol](#guacamole-protocol)
   - [Session Recording](#guacamole-session-recording)
   - [REST API](#guacamole-rest-api)
   - [Deployment (Docker & Kubernetes)](#guacamole-deployment)
   - [Recent Releases](#guacamole-recent-releases)
3. [noVNC](#novnc)
   - [Architecture & HTML5 Client](#novnc-architecture)
   - [WebSocket Proxy (websockify)](#websockify)
   - [Embedding & Integration Patterns](#novnc-embedding)
4. [TigerVNC](#tigervnc)
   - [Server & Viewer](#tigervnc-server-viewer)
   - [Encoding & Performance](#tigervnc-encoding)
   - [Recent Developments](#tigervnc-recent)
5. [FreeRDP](#freerdp)
   - [Library Architecture](#freerdp-architecture)
   - [Codec & Display Support](#freerdp-codecs)
   - [Security Features](#freerdp-security)
   - [Recent Releases](#freerdp-recent)
6. [xrdp](#xrdp)
   - [Architecture](#xrdp-architecture)
   - [TLS & Authentication](#xrdp-tls)
   - [Session Management](#xrdp-session-management)
7. [Weston RDP Backend](#weston-rdp)
   - [Headless Wayland Compositor](#weston-headless)
   - [RDP Backend Operation](#weston-rdp-operation)
   - [Container Deployment](#weston-container)
8. [Xvfb (Virtual Framebuffer)](#xvfb)
   - [Architecture](#xvfb-architecture)
   - [Container Patterns](#xvfb-container-patterns)
   - [Integration with VNC/noVNC](#xvfb-vnc-integration)
9. [GNOME Remote Desktop](#gnome-remote-desktop)
   - [PipeWire-Based Architecture](#gnome-pipewire)
   - [Portal-Mediated Capture](#gnome-portal)
   - [RDP/VNC Backends](#gnome-backends)
   - [Recent Improvements](#gnome-recent)
10. [WebRTC for Remote Desktop](#webrtc)
    - [RTCPeerConnection & Data Channels](#webrtc-peer)
    - [STUN/TURN Infrastructure](#webrtc-stun-turn)
    - [WebRTC Desktop Implementations](#webrtc-implementations)
    - [Latency & Performance](#webrtc-performance)
11. [Protocol Comparison](#protocol-comparison)
    - [VNC vs RDP vs WebRTC](#vnc-rdp-webrtc)
    - [Feature Matrix](#feature-matrix)
    - [Security Comparison](#security-comparison)
12. [CUA Gateway Deployment Patterns](#cua-deployment)
    - [MVP Architecture Options](#mvp-options)
    - [Recommended Stack](#recommended-stack)
    - [Evidence Collection via Remote Desktop](#evidence-collection)
13. [Clawdstrike Integration Notes](#clawdstrike-integration)
14. [References](#references)

---

## Overview

For a CUA gateway that needs to control "real desktops" (beyond browser-only), the gateway must provide:

1. **A controlled display surface** where applications run (virtual or physical)
2. **A remote access protocol** that the gateway uses to view and interact with that surface
3. **Session recording** to produce evidence for receipts
4. **Input injection** that is mediated exclusively through the gateway

The key architectural principle is: **the gateway is the only participant that speaks the remote desktop protocol**. The agent never directly accesses the display; it sends structured action requests to the gateway, which translates them into input events on the controlled desktop and captures evidence of the result.

### Corrections and caveats

- Portal-mediated Wayland control is user-consent and environment dependent; it is not a generic unattended injection API.
- RD protocol features (clipboard/file transfer/drive mapping) are frequent exfil paths and must default to deny.
- VNC simplicity is useful for prototyping, but production expectations should prefer RDP/WebRTC where latency and bandwidth matter.

### Pass #2 reviewer notes (2026-02-18)

- REVIEW-P2-CORRECTION: Latency and throughput values in this file are indicative planning ranges, not guarantees. Benchmark on your own runtime profile before setting SLOs.
- REVIEW-P2-GAP-FILL: For each protocol decision, add the exact enforcement hook in Clawdstrike terms (`policy event -> guard result -> audit event -> receipt metadata`).
- REVIEW-P2-CORRECTION: Treat non-primary references (blogs, vendor examples) as context only. Use project docs/specs as normative inputs for design decisions.

### Pass #2 execution criteria

- Desktop session denies clipboard/file-transfer by default and emits explicit policy events for every deny/allow.
- Every injected action yields pre/post evidence hashes and an auditable chain link in receipt metadata.
- Reconnect/session-recovery path preserves evidence continuity (no orphan actions).
- Latency SLOs are measured per deployment profile (not copied from generic tables).

### Pass #4 reviewer notes (2026-02-18)

- REVIEW-P4-CORRECTION: Any "recommended stack" language must include explicit threat-tier assumptions (dev, internal prod, internet-exposed multi-tenant).
- REVIEW-P4-GAP-FILL: Add protocol feature-policy matrix (clipboard, file transfer, audio, drive mapping, printing, session sharing) with explicit default action per mode (`observe`, `guardrail`, `fail_closed`).
- REVIEW-P4-CORRECTION: Transport security statements should name concrete auth and cert-validation requirements, not protocol-level defaults alone.

### Pass #4 implementation TODO block

- [x] Define `remote_desktop_policy_matrix.yaml` with per-protocol side-channel controls (`./remote_desktop_policy_matrix.yaml`).
- [x] Add end-to-end policy-event mapping for connect, input, clipboard, transfer, and disconnect paths (`./policy_event_mapping.md`, `./policy_event_mapping.yaml`).
- [x] Build repeatable latency harness (same host class, same codec, same frame size, warm/cold cache runs). *(`./repeatable_latency_harness.yaml`, `../../../../fixtures/benchmarks/remote-latency/v1/cases.json`, Pass #11)*
- [x] Add evidence continuity tests for reconnect, packet loss, and gateway restart scenarios (`./remote_session_continuity_suite.yaml`, `../../../../fixtures/policy-events/session-continuity/v1/cases.json`).

---

## Apache Guacamole

### Guacamole Architecture

Apache Guacamole (Apache-2.0 license) is a clientless remote desktop gateway that supports VNC, RDP, SSH, and Telnet. "Clientless" means users access remote desktops through a web browser with no plugins or client software required.

**System architecture:**

```
  ┌─────────────────────────────────────────────┐
  │           User's Web Browser                 │
  │  ┌─────────────────────────────────────┐    │
  │  │  Guacamole JavaScript Client        │    │
  │  │  (guacamole-common-js)              │    │
  │  │  - Canvas rendering                  │    │
  │  │  - Input capture (keyboard/mouse)    │    │
  │  │  - WebSocket transport               │    │
  │  └──────────────┬──────────────────────┘    │
  └─────────────────┼──────────────────────────┘
                    │ WebSocket (Guacamole protocol)
                    │
  ┌─────────────────▼──────────────────────────┐
  │           Guacamole Web Application         │
  │  (Java servlet in Tomcat)                   │
  │  - Authentication / authorization           │
  │  - Connection management                    │
  │  - Session recording configuration          │
  │  - REST API                                 │
  └─────────────────┬──────────────────────────┘
                    │ Guacamole protocol (TCP)
                    │
  ┌─────────────────▼──────────────────────────┐
  │           guacd (Native Proxy Daemon)       │
  │  (C, uses libguac)                          │
  │  - Protocol translation (VNC, RDP, SSH)     │
  │  - Client plugins (dynamically loaded)      │
  │  - Session recording (protocol dumps)       │
  │  - Audio/video encoding                     │
  └─────────────────┬──────────────────────────┘
                    │ VNC / RDP / SSH
                    │
  ┌─────────────────▼──────────────────────────┐
  │        Remote Desktop Server                │
  │  (VNC server, RDP server, SSH server)       │
  └────────────────────────────────────────────┘
```

**Key architectural properties:**

- **Protocol agnosticism**: The web application and client only understand the Guacamole protocol. guacd handles all remote desktop protocol translation. Adding support for a new protocol only requires a new guacd plugin.
- **Separation of concerns**: Authentication, authorization, and connection management are in the Java web app; raw protocol handling is in the C daemon (guacd).
- **Stateless web tier**: The web application can be scaled horizontally; guacd handles the stateful protocol connections.
- **Extensible auth**: Supports database (MySQL/PostgreSQL), LDAP, TOTP, header-based, OpenID Connect, SAML, and custom auth extensions.

### Guacamole Protocol

The Guacamole protocol is a custom protocol designed for remote display rendering and event transport. It operates at a higher level than VNC/RDP, abstracting the actual remote desktop protocol away from the client.

**Protocol characteristics:**
- Text-based, human-readable instruction format
- Instructions are comma-delimited with length-prefixed fields
- Supports drawing operations, audio, clipboard, file transfer
- Bidirectional: client sends input events, server sends display updates

**Instruction categories:**

| Category | Examples | Description |
|----------|----------|-------------|
| Drawing | `png`, `rect`, `copy`, `cfill` | Render graphics on the client canvas |
| Streaming | `img`, `blob`, `ack`, `end` | Transfer binary data (images, files) |
| Input | `mouse`, `key` | Keyboard and mouse events from client |
| Control | `sync`, `disconnect`, `nop` | Session lifecycle and synchronization |
| Audio | `audio` | Audio stream from remote session |
| Clipboard | `clipboard` | Clipboard content transfer |

**CUA gateway relevance:**
- The protocol acts as a natural mediation point: the gateway can inspect, filter, and log every instruction
- Drawing instructions can be replayed for audit (protocol dumps are essentially recordings)
- Input events are explicit and inspectable (coordinates, key codes)
- Clipboard and file transfer can be policy-gated at the protocol level

### Guacamole Session Recording

Guacamole supports recording sessions at the protocol level, which is distinct from and more efficient than raw video capture.

**Recording mechanism:**
- Sessions are recorded as **Guacamole protocol dumps** (raw instruction streams)
- Recording is configured per-connection in the Guacamole admin interface
- The recording file captures every drawing instruction, input event, and timing

**Playback options:**

1. **In-browser playback**: Guacamole can play back recordings directly in the browser using its JavaScript client. The recording is re-rendered in real time, producing a faithful reproduction of the session.

2. **Video conversion (guacenc)**: The `guacenc` utility converts protocol dumps to standard video files.

```bash
# Convert recording to MPEG-4 video
guacenc /path/to/recording

# Output: /path/to/recording.m4v
# Default: 640x480, 2 Mbps bitrate

# Custom resolution
guacenc -s 1920x1080 /path/to/recording

# Custom resolution and bitrate
guacenc -s 1280x720 -r 4000000 /path/to/recording
```

**guacenc internals:**
- Processes Guacamole protocol instruction streams
- Renders frames using the same logic as the web client
- Encodes to MPEG-4 using FFmpeg libraries (libavcodec, libavformat, libswscale)
- Preserves timing from the original session

**Advantages over raw video recording:**
- **Smaller file sizes**: Protocol dumps are much smaller than raw video
- **Lossless fidelity**: Re-rendering produces pixel-perfect output
- **Searchable**: Protocol instructions can be parsed for specific events
- **Flexible output**: Can generate video at any resolution/quality after the fact
- **Timestamped events**: Input events (clicks, keystrokes) have exact timestamps

**CUA gateway relevance:**
- Protocol dumps serve as a natural receipt artifact
- Each input event in the dump corresponds to an agent action
- Dumps can be hashed for tamper-evident chains
- Video conversion provides human-reviewable audit artifacts
- In-browser playback enables real-time monitoring

### Guacamole REST API

Guacamole provides a REST API for programmatic management:

**Authentication:**
```bash
# Obtain auth token
curl -X POST "https://guacamole.example.com/api/tokens" \
  -d "username=admin&password=secret"
# Returns: { "authToken": "...", "username": "admin", ... }
```

**Connection management:**
```bash
# List connections
curl -H "Guacamole-Token: $TOKEN" \
  "https://guacamole.example.com/api/session/data/postgresql/connections"

# Create connection
curl -X POST -H "Content-Type: application/json" \
  -H "Guacamole-Token: $TOKEN" \
  "https://guacamole.example.com/api/session/data/postgresql/connections" \
  -d '{
    "parentIdentifier": "ROOT",
    "name": "agent-desktop-1",
    "protocol": "vnc",
    "parameters": {
      "hostname": "desktop-container-1",
      "port": "5900",
      "password": "...",
      "recording-path": "/recordings",
      "recording-name": "session-${GUAC_DATE}-${GUAC_TIME}"
    }
  }'
```

**Key API endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tokens` | POST | Authenticate, get token |
| `/api/session/data/{source}/connections` | GET/POST | List/create connections |
| `/api/session/data/{source}/connections/{id}` | GET/PUT/DELETE | Manage connection |
| `/api/session/data/{source}/connections/{id}/parameters` | GET | Get connection parameters |
| `/api/session/data/{source}/activeConnections` | GET | List active sessions |
| `/api/session/data/{source}/history/connections` | GET | Connection history |
| `/api/session/data/{source}/users` | GET/POST | User management |

**AUDIT permission (v1.6.0):** A new permission type for read-only access to session history, useful for monitoring and compliance without full admin access.

### Guacamole Deployment

**Docker deployment (typical 3-container setup):**

```yaml
# docker-compose.yml
version: "3.9"
services:
  guacd:
    image: guacamole/guacd:1.6.0
    restart: unless-stopped
    volumes:
      - ./recordings:/recordings
    ports:
      - "4822:4822"

  guacamole:
    image: guacamole/guacamole:1.6.0
    restart: unless-stopped
    environment:
      GUACD_HOSTNAME: guacd
      GUACD_PORT: 4822
      POSTGRESQL_HOSTNAME: postgres
      POSTGRESQL_DATABASE: guacamole_db
      POSTGRESQL_USER: guacamole
      POSTGRESQL_PASSWORD: secret
      RECORDING_SEARCH_PATH: /recordings
    ports:
      - "8080:8080"
    depends_on:
      - guacd
      - postgres

  postgres:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_DB: guacamole_db
      POSTGRES_USER: guacamole
      POSTGRES_PASSWORD: secret
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

**Kubernetes deployment:**

```yaml
# guacd Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guacd
spec:
  replicas: 1
  selector:
    matchLabels:
      app: guacd
  template:
    metadata:
      labels:
        app: guacd
    spec:
      containers:
      - name: guacd
        image: guacamole/guacd:1.6.0
        ports:
        - containerPort: 4822
        volumeMounts:
        - name: recordings
          mountPath: /recordings
      volumes:
      - name: recordings
        persistentVolumeClaim:
          claimName: guacamole-recordings
```

**Additional Kubernetes options:**
- [guacamole-operator](https://github.com/guacamole-operator/guacamole-operator): Kubernetes operator for Guacamole lifecycle management
- Helm charts available from the community
- Google Cloud Architecture Center reference deployment on GKE

**Docker v1.6.0 improvements:**
- All configuration properties automatically mapped from environment variables
- ARM CPU support (not just x86)

### Guacamole Recent Releases

**v1.6.0 (June 22, 2025):**
- Major rewrite of the server-side protocol optimizer in guacd
- Enhanced rendering pipeline: better responsiveness, reduced bandwidth
- All Docker environment variables auto-mapped to config properties
- ARM Docker image support
- Batch connection import
- AUDIT permission for read-only history access
- Duo v4 authentication support
- Configurable case sensitivity for usernames

---

## noVNC

### noVNC Architecture

noVNC (MPL-2.0 license) is an HTML5 VNC client that runs entirely in the browser. It implements the VNC/RFB protocol using JavaScript, rendering to an HTML Canvas element and communicating via WebSockets.

**Architecture:**

```
  ┌──────────────────────────────────┐
  │        Web Browser                │
  │  ┌────────────────────────────┐  │
  │  │  noVNC JavaScript Client   │  │
  │  │  - RFB protocol impl       │  │
  │  │  - Canvas rendering         │  │
  │  │  - Input event capture      │  │
  │  │  - WebSocket transport      │  │
  │  └────────────┬───────────────┘  │
  └───────────────┼──────────────────┘
                  │ WebSocket (wss://)
                  │
  ┌───────────────▼──────────────────┐
  │      websockify Proxy             │
  │  (WebSocket <-> TCP bridge)       │
  │  - SSL/TLS termination           │
  │  - Mini web server (--web)       │
  │  - Auth plugins                  │
  └───────────────┬──────────────────┘
                  │ TCP (RFB protocol)
                  │
  ┌───────────────▼──────────────────┐
  │      VNC Server                   │
  │  (TigerVNC, x11vnc, etc.)       │
  └──────────────────────────────────┘
```

**Key properties:**
- Zero-install client (runs in any modern browser)
- Supports clipboard, resizing, mouse events, keyboard events
- Encryption via WebSocket Secure (wss://)
- Can connect directly to VNC servers with native WebSocket support (x11vnc, libvncserver, QEMU) without websockify

### websockify

websockify is noVNC's companion project that bridges WebSocket connections to raw TCP sockets.

**Primary implementation:** Python (also available in Node.js, C, Clojure, Ruby)

**Features:**
- **SSL/TLS**: Auto-detected from first byte; supports wss:// connections
- **Mini web server**: `--web DIR` serves static files on the same port as the WebSocket proxy
- **Authentication plugins**: Token-based, basic auth, and custom plugins
- **Binary data**: Full binary WebSocket frame support for efficient VNC data transfer

**Usage:**

```bash
# Basic: proxy WebSocket port 6080 to VNC on localhost:5900
websockify 6080 localhost:5900

# With TLS and web server
websockify --cert=server.pem --web=/path/to/novnc 6080 localhost:5900

# Token-based multiplexing (multiple VNC servers)
websockify --token-plugin TokenFile --token-source /etc/websockify/tokens 6080
# Token file maps: session1: localhost:5901
#                  session2: localhost:5902
```

### noVNC Embedding

noVNC can be embedded into web applications for CUA gateway UIs:

**iframe embedding:**
```html
<iframe src="https://gateway.example.com/vnc.html?autoconnect=true&resize=scale"
        width="1280" height="720"></iframe>
```

**JavaScript API embedding:**
```javascript
import RFB from '@novnc/novnc/core/rfb';

// Connect to VNC server via WebSocket proxy
const rfb = new RFB(
  document.getElementById('screen'),
  'wss://gateway.example.com/websockify',
  { credentials: { password: 'vnc-password' } }
);

// Events
rfb.addEventListener('connect', () => console.log('Connected'));
rfb.addEventListener('disconnect', (e) => console.log('Disconnected'));
rfb.addEventListener('clipboard', (e) => {
  // Clipboard data from remote -- can be policy-filtered
  console.log('Clipboard:', e.detail.text);
});

// Capture screenshot from canvas
const canvas = document.getElementById('screen').querySelector('canvas');
const dataUrl = canvas.toDataURL('image/png');
```

**Query string options:**
- `autoconnect=true` - Connect immediately on page load
- `resize=scale|remote|off` - Display size handling
- `reconnect=true` - Auto-reconnect on disconnect
- `reconnect_delay=2000` - Reconnection delay (ms)

---

## TigerVNC

### TigerVNC Server & Viewer

TigerVNC (GPL-2.0 license) is a high-performance, multi-platform VNC implementation.

**Components:**

| Component | Description | Platform |
|-----------|-------------|----------|
| `Xvnc` | Combined X server + VNC server | Linux |
| `x0vncserver` | VNC server for existing X display | Linux |
| `w0vncserver` | VNC server for Wayland (new v1.16) | Linux (Wayland) |
| `vncviewer` | VNC viewer/client | Windows, macOS, Linux |
| `vncpasswd` | Password management | Linux |

**Xvnc operation:**
```bash
# Start Xvnc on display :1 with 1920x1080 resolution
vncserver :1 -geometry 1920x1080 -depth 24 -SecurityTypes TLSVnc

# VNC clients connect to port 5901 (5900 + display number)
```

### TigerVNC Encoding & Performance

| Encoding | Description | Best For |
|----------|-------------|----------|
| **Tight** | Tight encoding with libjpeg-turbo acceleration | General use (default) |
| **JPEG** | JPEG compression of screen regions | Photo-heavy content |
| **ZRLE** | Zlib Run-Length Encoding | Compression/speed balance |
| **Hextile** | 16x16 tile-based encoding | Low CPU environments |
| **H.264** | H.264 video encoding (PiKVM support) | Video/animation content |
| **Raw** | Uncompressed pixels | High-bandwidth LAN |

**Performance features:**
- **Automatic encoding selection**: Viewer tests connection speed and selects optimal encoding/pixel format
- **libjpeg-turbo**: Hardware-accelerated JPEG encoding for Tight encoding
- **JPEG quality**: Configurable 0-9 (default 8)
- **Lossless compression**: Configurable 0-9 (default 2)
- **Adaptive updates**: Sends only changed regions

### TigerVNC Recent Developments

**v1.16.0 (beta, 2025):**
- New keyboard shortcut system
- System key sending in windowed mode
- New `w0vncserver` for Wayland desktops
- Improved resize responsiveness
- H.264 encoding support (PiKVM integration)

---

## FreeRDP

### FreeRDP Library Architecture

FreeRDP (Apache-2.0 license) is a free implementation of the Remote Desktop Protocol. It provides both client and server libraries.

**Architecture:**

```
  ┌────────────────────────────────────────────┐
  │               FreeRDP Clients               │
  │  ┌──────────┐ ┌──────────┐ ┌────────────┐ │
  │  │ xfreerdp  │ │ wlfreerdp│ │ SDL client  │ │
  │  │ (X11)     │ │ (Wayland)│ │ (SDL3)      │ │
  │  └─────┬─────┘ └────┬────┘ └─────┬──────┘ │
  └────────┼─────────────┼────────────┼────────┘
           │             │            │
  ┌────────▼─────────────▼────────────▼────────┐
  │              libfreerdp                     │
  │  - RDP protocol implementation              │
  │  - TLS/NLA/CredSSP authentication          │
  │  - Codec pipeline (RemoteFX, H.264, etc.)  │
  │  - Clipboard, audio, drive redirection     │
  │  - Channel management                       │
  └────────┬───────────────────────────────────┘
           │
  ┌────────▼───────────────────────────────────┐
  │              libfreerdp-server              │
  │  - Server-side RDP implementation           │
  │  - Used by weston-rdp, xrdp, etc.          │
  └────────────────────────────────────────────┘
```

**Key properties:**
- **Apache-2.0 license**: Permissive, suitable for embedding in proprietary products
- **C library**: Low-level, high-performance, linkable from any language
- **Multi-client**: X11 (xfreerdp), Wayland (wlfreerdp), SDL3 (sdl-freerdp)
- **Server library**: Powers server-side RDP in Weston and xrdp

### FreeRDP Codec & Display Support

| Codec | Description | Use Case |
|-------|-------------|----------|
| **RemoteFX** | Microsoft progressive codec | Windows Server environments |
| **NSCodec** | RDP bitmap codec | General bitmaps |
| **H.264 (AVC/444)** | Hardware-accelerated video | High-motion content |
| **Progressive** | JPEG-like progressive refinement | Bandwidth optimization |
| **Planar** | Raw planar bitmap | Lossless regions |
| **Interleaved** | Run-length encoded bitmaps | Legacy compatibility |

**Display features (v3.22):**
- Overhauled SDL3-based client UI
- High DPI (HiDPI) support
- Dynamic resolution scaling
- Multi-monitor support
- Graphics pipeline (GFX) support

### FreeRDP Security Features

| Feature | Description |
|---------|-------------|
| **TLS** | Transport-layer encryption for all RDP traffic |
| **NLA** | CredSSP-based pre-authentication before full connection |
| **RDP Security** | Legacy encryption mode (weaker, compatibility) |
| **Smart card auth** | Certificate-based authentication |
| **Kerberos** | Domain authentication |
| **Certificate validation** | Server cert verification with configurable policies |

**Security updates (2025-2026):**
- v3.21.0: Input data validation fixes, CVE-2026-23530 through CVE-2026-23884
- v3.22: Client-side and proxy code security fixes
- Codec advanced length checks, glyph fixes, double-free fixes

### FreeRDP Recent Releases

**v3.22 (February 2026):**
- Complete overhaul of SDL3-based client UI
- HiDPI improvements, dynamic resolution scaling
- Multiple CVE security fixes

**v3.21.0 (January 2026):**
- Input validation bugfixes, multiple CVE patches

**v3.20.x (December 2025):**
- Performance improvements, protocol compliance

**Release cadence:** Active monthly releases through 2025-2026.

---

## xrdp

### xrdp Architecture

xrdp (Apache-2.0 license) is an open-source RDP server for Linux/Unix systems.

**Architecture:**

```
  ┌─────────────────────────────────┐
  │      RDP Client                  │
  │  (Windows MSTSC, FreeRDP, etc.) │
  └──────────────┬──────────────────┘
                 │ RDP Protocol (TLS)
  ┌──────────────▼──────────────────┐
  │            xrdp                  │
  │  - RDP protocol server           │
  │  - TLS termination              │
  │  - Authentication               │
  └──────────────┬──────────────────┘
                 │
  ┌──────────────▼──────────────────┐
  │         xrdp-sesman              │
  │  (Session Manager)               │
  │  - User session lifecycle        │
  │  - Desktop environment launch    │
  └──────────────┬──────────────────┘
                 │
  ┌──────────────▼──────────────────┐
  │     Backend (one of):            │
  │  - Xvnc (TigerVNC)             │
  │  - X11rdp (custom)              │
  │  - Xorg (xorgxrdp module)      │
  └──────────────────────────────────┘
```

### xrdp TLS & Authentication

**TLS configuration (xrdp.ini):**

```ini
[Globals]
; Security layer: negotiate, tls, rdp
security_layer=tls

; TLS certificate and key (PEM format)
certificate=/etc/xrdp/cert.pem
key_file=/etc/xrdp/key.pem

; Cipher suites and protocol versions
tls_ciphers=HIGH:!aNULL:!eNULL:!EXPORT
ssl_protocols=TLSv1.2,TLSv1.3
```

| Security Layer | Description | Level |
|----------------|-------------|-------|
| `tls` | Enhanced RDP Security via TLS | High |
| `negotiate` | Client/server negotiate best available | Varies |
| `rdp` | Classic RDP security (weak) | Low (legacy) |

**Authentication:** PAM (system auth), Active Directory via PAM + SSSD/Winbind, custom modules.

### xrdp Session Management

**Multi-session support:**
- Independent desktop session per user
- Sessions persist across disconnections (reconnectable)
- Configurable session limits per user
- Session timeout/idle settings

**CUA gateway relevance:**
- Standard RDP endpoint for Linux desktops
- TLS encryption by default
- Session lifecycle aligns with gateway sessions
- Combinable with Xvfb or Xorg for headless operation

---

## Weston RDP Backend

### Headless Wayland Compositor

Weston (MIT license) is the reference Wayland compositor. Its RDP backend provides a unique capability: a headless Wayland compositor accessible only via RDP.

**Key differentiator:** Unlike X11-based solutions, Weston's RDP backend is an integrated compositor + remote display. No physical display, no GPU required, no local input devices. The RDP connection is the only interaction path.

### Weston RDP Operation

**Starting Weston with RDP backend:**

```bash
# Basic RDP backend
weston --backend=rdp

# With TLS (required for production)
weston --backend=rdp \
  --rdp-tls-cert=/path/to/cert.pem \
  --rdp-tls-key=/path/to/key.pem

# With specific resolution
weston --backend=rdp --width=1920 --height=1080
```

**Configuration (weston.ini):**
```ini
[core]
backend=rdp

[rdp]
tls-cert=/etc/weston/cert.pem
tls-key=/etc/weston/key.pem
refresh-rate=60

[output]
name=rdp1
mode=1920x1080
```

**Technical characteristics:**
- Memory buffer as framebuffer (no GPU)
- Pixman software renderer
- Each RDP client gets its own seat (keyboard + pointer)
- Multi-seat support for multi-user scenarios
- RDP transport provided by FreeRDP library (libfreerdp-server)

### Weston Container Deployment

```dockerfile
FROM fedora:latest

RUN dnf install -y weston freerdp

# Generate TLS certificate
RUN openssl req -x509 -newkey rsa:2048 \
  -keyout /etc/weston/key.pem \
  -out /etc/weston/cert.pem \
  -days 365 -nodes -subj "/CN=weston-rdp"

EXPOSE 3389

CMD ["weston", "--backend=rdp", \
     "--rdp-tls-cert=/etc/weston/cert.pem", \
     "--rdp-tls-key=/etc/weston/key.pem"]
```

**CUA gateway advantages:**
- **No GPU required**: Pure software rendering, ideal for containers
- **No input devices**: RDP is the only interaction path (matches gateway model exactly)
- **Wayland-native**: Applications benefit from Wayland's security model (client isolation)
- **Minimal attack surface**: No X11, no physical display stack
- **Standard RDP**: Any RDP client can connect

---

## Xvfb (Virtual Framebuffer)

### Xvfb Architecture

Xvfb (X virtual framebuffer) implements the X11 protocol entirely in memory, without any physical display hardware.

```
  ┌─────────────────────────────────────────┐
  │            Xvfb Process                  │
  │  ┌───────────────────────────────────┐  │
  │  │  X11 Protocol Server               │  │
  │  └──────────────┬────────────────────┘  │
  │  ┌──────────────▼────────────────────┐  │
  │  │  Virtual Framebuffer               │  │
  │  │  (in-memory pixel buffer)          │  │
  │  │  - No GPU needed                   │  │
  │  │  - Configurable resolution/depth   │  │
  │  └──────────────────────────────────┘  │
  └─────────────────────────────────────────┘
```

**Starting Xvfb:**
```bash
# Start on display :99 with 1920x1080x24
Xvfb :99 -screen 0 1920x1080x24 &
export DISPLAY=:99
```

**Key properties:**
- Extremely lightweight (no GPU, no hardware dependencies)
- Standard X11 protocol (all X11 apps work unmodified)
- Configurable resolution, color depth, screen count
- Available on virtually all Linux distributions

### Xvfb Container Patterns

**Pattern 1: Xvfb + x11vnc + noVNC (most common)**

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
  xvfb x11vnc novnc websockify fluxbox xterm

COPY entrypoint.sh /
CMD ["/entrypoint.sh"]
```

```bash
#!/bin/bash
# entrypoint.sh
Xvfb :0 -screen 0 1920x1080x24 &
export DISPLAY=:0
fluxbox &
x11vnc -display :0 -forever -nopw -shared -rfbport 5900 &
websockify --web=/usr/share/novnc 6080 localhost:5900 &
wait
```

**Pattern 2: TigerVNC Xvnc (combined X + VNC server)**

```bash
# Replaces both Xvfb and separate VNC server
Xvnc :0 -geometry 1920x1080 -depth 24 -SecurityTypes None
```

**Pattern 3: Headless Chrome in container**

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y xvfb chromium
CMD xvfb-run -a chromium --no-sandbox --remote-debugging-port=9222
```

### Xvfb + VNC Integration

**Typical stack for CUA:**

```
  noVNC + websockify  <--- Web monitoring UI
       │ (WebSocket)
  x11vnc / Xvnc       <--- VNC server
       │ (X11)
  Xvfb (:0)           <--- Virtual display
       │
  Applications         <--- Chrome, Firefox, LibreOffice
```

**CUA gateway relevance:**
- Simplest headless display for Linux containers
- Well-understood, decades of production use
- Main limitation: X11 security model is weak (clients can snoop on each other within the same display)

---

## GNOME Remote Desktop

### PipeWire-Based Architecture

GNOME Remote Desktop (`gnome-remote-desktop`) uses PipeWire for screen content transport, integrating tightly with Mutter (GNOME's compositor).

```
  Mutter (GNOME Compositor)
       │ Portal D-Bus API
  xdg-desktop-portal-gnome
       │ (mediates access)
  PipeWire
       │ (low-latency streams)
  gnome-remote-desktop daemon
       │ (RDP/VNC backends)
  Remote clients
```

### Portal-Mediated Capture

GNOME uses XDG Desktop Portal for screen capture and remote input, aligning with Wayland's security model:

| Interface | Purpose |
|-----------|---------|
| `org.freedesktop.portal.RemoteDesktop` | Combined capture + input |
| `org.freedesktop.portal.ScreenCast` | Screen capture only |
| `org.freedesktop.portal.InputCapture` | Input capture/barrier API |

**Security advantages:**
- Compositor controls all access (no client-to-client snooping)
- Portal mediates user consent
- PipeWire runs outside application sandbox
- Access is revocable at any time

**Caveat for CUA:** Portal-mediated access requires user consent in most configurations, making it unsuitable for fully unattended agent operation unless the desktop environment is configured to auto-approve specific sessions.

### GNOME Remote Desktop Backends

**RDP backend (primary):**
- Based on FreeRDP server library
- TLS + NLA authentication
- Standard RDP clients connect
- Dynamic resolution changes

**Configuration (GNOME 49+):**
```bash
grdctl rdp enable
grdctl rdp set-credentials --username=user --password=pass
grdctl rdp set-tls-cert /path/to/cert.pem
grdctl rdp set-tls-key /path/to/key.pem
grdctl status
```

### GNOME Remote Desktop Recent Improvements

**GNOME 49 "Brescia" (September 2025):**
- Multi-touch input support
- Relative mouse input (gaming/precise control)
- Extended virtual monitors
- Command-line configuration (grdctl)
- PipeWire performance optimizations

**CUA gateway considerations:**
- Best when you need a full GNOME session
- Portal-mediated access aligns with security-first design
- Heavier than Xvfb/Weston (requires full GNOME stack)
- Not suitable for minimal container deployments

---

## WebRTC for Remote Desktop

### RTCPeerConnection & Data Channels

WebRTC enables the lowest-latency browser-to-server media streaming, making it attractive for responsive agent interaction.

| Component | Remote Desktop Role |
|-----------|---------------------|
| `RTCPeerConnection` | Peer connection, media/data management |
| Video track | Desktop video stream |
| `RTCDataChannel` | Low-latency input events |
| ICE | NAT traversal |
| DTLS | Data channel encryption |
| SRTP | Media stream encryption |

**Data channel for input:**
```javascript
const dc = peerConnection.createDataChannel('input', {
  ordered: true,
  maxRetransmits: 0  // Prefer low latency
});

dc.onmessage = (event) => {
  const input = JSON.parse(event.data);
  switch (input.type) {
    case 'mousemove': injectMouseMove(input.x, input.y); break;
    case 'mousedown': injectMouseClick(input.x, input.y, input.button); break;
    case 'keydown': injectKeyPress(input.keyCode); break;
  }
};
```

### STUN/TURN Infrastructure

- **STUN**: Discovers public IP/port; lightweight, stateless; 75-80% success rate for direct connections
- **TURN**: Relays media when direct connection fails; needed for ~20-25% of connections; adds latency

**For CUA gateway:** In controlled environments (same VPC/network), STUN/TURN may not be needed. Direct connections within container networks avoid NAT traversal entirely.

### WebRTC Desktop Implementations

**Selkies-GStreamer:**
- Open-source WebRTC remote desktop platform (started by Google engineers)
- GStreamer pipeline: capture, encode (H.264/VP8/VP9 with GPU acceleration), stream via WebRTC
- Audio via Opus codec
- Container-native: designed for unprivileged Docker and Kubernetes
- No special device access required

```bash
docker run --name selkies \
  -e DISPLAY_SIZEW=1920 -e DISPLAY_SIZEH=1080 \
  -e ENCODER=x264enc \
  -p 8080:8080 \
  ghcr.io/selkies-project/selkies-gstreamer:latest
```

**Neko:**
- Self-hosted virtual browser in Docker with WebRTC
- Smooth video vs. noVNC (WebRTC instead of images over WebSocket)
- Built-in audio support
- Multi-user with presenter/viewer roles

```bash
docker run -d --name neko \
  -p 8080:8080 -p 52000-52100:52000-52100/udp \
  -e NEKO_SCREEN=1920x1080@30 \
  -e NEKO_PASSWORD=user \
  m1k1o/neko:firefox
```

### WebRTC Performance

> REVIEW-P2-CORRECTION: Treat the table below as directional only. Network path, TURN usage, codec choice, frame size, and host CPU/GPU profile can shift results significantly.

| Metric | WebRTC | VNC (Tight) | RDP |
|--------|--------|-------------|-----|
| **Typical latency** | 50-250ms | 100-500ms | 50-200ms |
| **Codec support** | H.264, VP8, VP9, AV1 | JPEG, ZRLE, H.264 | RemoteFX, H.264 |
| **HW acceleration** | Yes (GPU encode/decode) | Limited (libjpeg-turbo) | Yes |
| **Audio** | Built-in (Opus) | Not standard | Built-in |
| **Encryption** | Mandatory (DTLS+SRTP) | Optional (TLS wrap) | TLS standard |
| **Browser client** | Native (no plugins) | noVNC (JavaScript) | Via Guacamole |

---

## Protocol Comparison

### VNC vs RDP vs WebRTC

| Aspect | VNC | RDP | WebRTC |
|--------|-----|-----|--------|
| **Protocol type** | Pixel-based framebuffer | Instruction-based rendering | Codec-based streaming |
| **How it works** | Captures screen, compresses, sends pixel diffs | Sends drawing instructions (GDI/GFX) | Encodes video stream, client decodes |
| **Bandwidth** | Higher (pixel data) | Lower (instructions) | Adaptive (codec-dependent) |
| **Latency** | Medium-High | Low-Medium | Lowest |
| **CPU (server)** | Low-Medium | Low | Medium-High (encoding) |
| **Platform origin** | Cross-platform (RFB) | Windows (Microsoft) | Web standard (W3C/IETF) |
| **Open impls** | TigerVNC, x11vnc | FreeRDP, xrdp | Selkies, Neko |

### Feature Matrix

| Feature | VNC (TigerVNC) | RDP (xrdp/FreeRDP) | WebRTC (Selkies) | Guacamole |
|---------|---------------|---------------------|-------------------|-----------|
| **License** | GPL-2.0 | Apache-2.0 | Apache-2.0/MIT | Apache-2.0 |
| **Audio** | No (standard) | Yes | Yes (Opus) | Yes (via backend) |
| **Clipboard** | Yes | Yes | Via data channel | Yes |
| **File transfer** | No (standard) | Yes | No (standard) | Yes |
| **Session recording** | External | External | External | Built-in |
| **Dynamic resolution** | Limited | Yes | Yes | Via backend |
| **TLS encryption** | Optional (wrap) | Built-in | Mandatory (DTLS) | Via backend |
| **Browser client** | noVNC | Via Guacamole | Native | Built-in |
| **Container-friendly** | Very (Xvfb+VNC) | Good (xrdp) | Good (Selkies) | Good |
| **GPU required** | No | No | Optional (helps) | No |

### Security Comparison

| Aspect | VNC | RDP | WebRTC |
|--------|-----|-----|--------|
| **Transport** | Optional TLS | TLS built-in | DTLS+SRTP mandatory |
| **Authentication** | Password-only | NLA+Kerberos+smart cards | Application-defined |
| **MITM protection** | Vulnerable without TLS | Protected with NLA | DTLS fingerprints |
| **Clipboard** | Uncontrolled | Policy-controllable | Application-defined |
| **File transfer** | N/A | Controllable via policy | N/A (not standard) |

---

## CUA Gateway Deployment Patterns

### MVP Architecture Options

**Option A: Xvfb + VNC + Guacamole (recommended for MVP)**

```
  Agent Request
       │
  CUA Gateway (policy + evidence)
       │ (Guacamole protocol)
  Apache Guacamole (guacd + web app)
       │ (VNC/RFB)
  Desktop Container (Xvfb + Xvnc + fluxbox + apps)
```

**Advantages:** Session recording out of the box, REST API, web UI monitoring, protocol dumps as receipt artifacts, production-proven.

**Option B: Weston RDP + FreeRDP (more secure)**

```
  Agent Request
       │
  CUA Gateway (policy + evidence + FreeRDP client)
       │ (RDP)
  Desktop Container (Weston RDP backend + Wayland apps)
```

**Advantages:** No X11, RDP-only access, no GPU, Wayland client isolation. **Disadvantages:** Fewer native Wayland apps, XWayland needed for X11 apps.

**Option C: WebRTC via Selkies-GStreamer (lowest latency)**

```
  Agent Request
       │
  CUA Gateway (policy + evidence)
       │ (WebRTC signaling + media)
  Selkies-GStreamer (GStreamer + Xvfb/Weston + apps)
```

**Advantages:** Lowest latency, HW-accelerated encoding, browser-native client. **Disadvantages:** Complex signaling, session recording needs additional layer.

### Recommended Stack

**Phase B (MVP for desktop runtime):**

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Display server | Xvfb | Simplest, most mature |
| VNC server | TigerVNC (Xvnc) | Combined X + VNC |
| RD gateway | Apache Guacamole | Built-in recording, REST API |
| Container | Docker (Xvfb + Xvnc) | Well-understood pattern |
| Recording | Guacamole protocol dumps + guacenc | Natural receipt artifacts |

**Phase C (hardening):**

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Display server | Weston (RDP backend) | Wayland security, RDP-only |
| Protocol | RDP (FreeRDP) | Better security than VNC |
| Isolation | Firecracker/gVisor | Stronger containment |
| Streaming | Selkies-GStreamer | When low latency is critical |

### Evidence Collection via Remote Desktop

**Multi-layer evidence pipeline:**

```
  Agent Action Request
       │
       ├── 1. Capture pre-action frame (via Guacamole/VNC)
       │      └── Hash: SHA-256(frame_png)
       │
       ├── 2. Execute action (inject input via gateway)
       │      └── Log: exact input events (coords, keys, timing)
       │
       ├── 3. Wait for visual stability
       │
       ├── 4. Capture post-action frame
       │      └── Hash: SHA-256(frame_png)
       │
       ├── 5. Compute diff (changed regions)
       │
       └── 6. Append to receipt chain
              └── event_hash = SHA-256(pre + post + action + prev_hash)
```

---

## Clawdstrike Integration Notes

### Mapping to existing infrastructure

- Normalize all remote desktop side effects into explicit policy events: `clipboard.read`, `clipboard.write`, `file.transfer`, `session.share`
- Record protocol metadata (connection id, codec, transport, auth mode) in receipt metadata for post-incident triage
- Force per-session ephemeral runtime images and immutable launch config digests into signed evidence

### Hardening checklist per protocol

| Flag | RDP | VNC | WebRTC |
|------|-----|-----|--------|
| Auth mode | NLA + TLS 1.2+ | VNC password + TLS tunnel | Signaling auth |
| Clipboard | Deny by default | Deny by default | Deny by default |
| File transfer | Deny by default | N/A | N/A |
| Idle timeout | Enforce | Enforce | Enforce |
| Recording | Guacamole dump | Guacamole dump | GStreamer capture |

### Gaps for agent team to fill

- Reproducible "desktop runtime profiles" (Xvfb + WM, Weston-RDP, GNOME RDP) with startup scripts and expected artifacts
- Recovery playbook for session desync and reconnect without evidence-chain breakage
- Measure end-to-end click-to-pixel latency for Weston-RDP vs Xvfb+VNC in identical host conditions

---

## References

- [Apache Guacamole Manual v1.6.0](https://guacamole.apache.org/doc/gug/)
- [Guacamole Architecture](https://guacamole.apache.org/doc/gug/guacamole-architecture.html)
- [Guacamole Session Recording](https://guacamole.apache.org/doc/gug/recording-playback.html)
- [Guacamole Docker](https://guacamole.apache.org/doc/gug/guacamole-docker.html)
- [noVNC](https://novnc.com/noVNC/)
- [noVNC Embedding](https://novnc.com/noVNC/docs/EMBEDDING.html)
- [websockify](https://github.com/novnc/websockify)
- [TigerVNC](https://tigervnc.org/)
- [FreeRDP](https://www.freerdp.com/)
- [FreeRDP GitHub](https://github.com/FreeRDP/FreeRDP)
- [xrdp](https://www.xrdp.org/)
- [xrdp TLS Wiki](https://github.com/neutrinolabs/xrdp/wiki/TLS-security-layer)
- [Weston Documentation](https://wayland.pages.freedesktop.org/weston/toc/running-weston.html)
- [Weston RDP Backend](https://www.hardening-consulting.com/en/posts/20131006an-overview-of-the-rdp-backend-in-weston.html)
- [GNOME Remote Desktop](https://github.com/GNOME/gnome-remote-desktop)
- [XDG Desktop Portal RemoteDesktop](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)
- [Selkies-GStreamer](https://github.com/selkies-project/selkies)
- [Neko Virtual Browser](https://github.com/m1k1o/neko)
- [guacamole-operator](https://github.com/guacamole-operator/guacamole-operator)
- [docker-weston-rdp](https://github.com/technic/docker-weston-rdp)
- [vnc-containers](https://github.com/silentz/vnc-containers)
