# Session Recording & Screen Capture Pipelines

> Research document for the Clawdstrike CUA Gateway project.
> Covers desktop/browser screen capture technologies, video encoding pipelines, frame hashing,
> diff computation, and the receipt evidence pipeline.

---

## Table of Contents

1. [Overview](#overview)
2. [Desktop Capture Technologies](#desktop-capture-technologies)
   - [FFmpeg Desktop Recording](#ffmpeg-desktop-recording)
   - [Apple ScreenCaptureKit](#apple-screencapturekit)
   - [Windows Desktop Duplication API](#windows-desktop-duplication-api)
   - [PipeWire + XDG ScreenCast Portal](#pipewire--xdg-screencast-portal)
3. [Browser Capture Technologies](#browser-capture-technologies)
   - [CDP Page.captureScreenshot](#cdp-pagecapturescreenshot)
   - [W3C Screen Capture API](#w3c-screen-capture-api)
4. [Protocol-Level Recording](#protocol-level-recording)
   - [Guacamole Session Recording](#guacamole-session-recording)
5. [Video Encoding and Codecs](#video-encoding-and-codecs)
   - [Codec Selection](#codec-selection)
   - [GPU Acceleration](#gpu-acceleration)
   - [FFmpeg Licensing](#ffmpeg-licensing)
6. [Frame Hashing](#frame-hashing)
   - [Cryptographic Hashing (SHA-256)](#cryptographic-hashing-sha-256)
   - [Perceptual Hashing](#perceptual-hashing)
7. [Diff Computation](#diff-computation)
   - [Pixel-Level Differencing](#pixel-level-differencing)
   - [Region-Based Change Detection](#region-based-change-detection)
   - [SSIM for Structural Similarity](#ssim-for-structural-similarity)
8. [Receipt Evidence Pipeline](#receipt-evidence-pipeline)
   - [Pipeline Architecture](#pipeline-architecture)
   - [Artifact Manifest and Signing](#artifact-manifest-and-signing)
   - [Retention and Redaction](#retention-and-redaction)
9. [Comparison Matrix](#comparison-matrix)
10. [Implications for CUA Gateway Design](#implications-for-cua-gateway-design)
11. [References](#references)

---

## Overview

A CUA gateway must capture verifiable evidence of every action an agent takes on the controlled desktop or browser. This evidence forms the foundation of the receipt system: cryptographically signed attestations that prove what the agent saw, what it did, and what happened as a result.

The session recording pipeline has several goals:

- **Pre/post action capture**: Capture the screen state immediately before and after every agent action.
- **Integrity**: Produce cryptographic hashes of every frame to enable tamper detection.
- **Similarity detection**: Use perceptual hashing and diff computation to identify what changed.
- **Continuous recording**: Optionally record the entire session as video for audit playback.
- **Storage efficiency**: Balance forensic completeness against storage costs.
- **Redaction**: Remove sensitive content (passwords, PII) before persistence.
- **Cross-platform**: Work across Linux, Windows, macOS, and browser-first deployments.

This document surveys capture technologies, encoding pipelines, hashing methods, and diff algorithms, and describes how they compose into a receipt evidence pipeline.

### Pass #3 reviewer notes (2026-02-18)

- REVIEW-P3-CORRECTION: Recording fidelity claims should be tied to explicit capture mode and codec settings; do not assume results transfer across pipelines.
- REVIEW-P3-GAP-FILL: Separate "forensic evidence artifacts" from "operator convenience artifacts" with different retention and integrity requirements.
- REVIEW-P3-CORRECTION: Any lossy transform before hash generation breaks evidentiary comparability; hash source frames prior to optional transcoding.

### Pass #3 execution criteria

- Evidence pipeline defines canonical hash input per artifact type (raw frame, redacted frame, video segment, protocol log).
- Receipt metadata includes capture configuration digest (tool version, codec params, frame cadence, timestamp source).
- Redaction step emits deterministic provenance fields (`rule_id`, `method`, `pre_hash`, `post_hash`).
- End-to-end replay can recompute manifest digests from stored artifacts without privileged side data.

---

## Desktop Capture Technologies

### FFmpeg Desktop Recording

**What it is.** FFmpeg is the universal multimedia framework for recording, converting, and streaming audio and video. For CUA, it serves as the primary tool for capturing desktop sessions into video files, individual frames, or streaming pipelines.

**Platform-specific capture devices.**

| Device | Platform | Description |
|--------|----------|-------------|
| `x11grab` | Linux (X11) | Captures from an X11 display server by reading the framebuffer directly |
| `kmsgrab` | Linux (DRM/KMS) | Captures via DRM (Direct Rendering Manager); lower overhead than x11grab, works with GPU-accelerated pipelines |
| `avfoundation` | macOS | Apple's multimedia framework for screen and camera capture |
| `dshow` (DirectShow) | Windows | Legacy Windows capture device |
| `gdigrab` | Windows | Captures via GDI (Graphics Device Interface); simpler than DirectShow |

**x11grab usage for CUA (Linux containers with Xvfb).**

```bash
# Record the entire Xvfb display at 10fps to H.264
ffmpeg -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -c:v libx264 -preset ultrafast -crf 23 \
    -y session.mp4

# Capture a single frame (screenshot) as PNG
ffmpeg -f x11grab -video_size 1920x1080 -i :99 \
    -frames:v 1 -y screenshot.png

# Stream to a pipe for real-time processing
ffmpeg -f x11grab -r 5 -video_size 1920x1080 -i :99 \
    -f rawvideo -pix_fmt rgb24 pipe:1 | \
    ./frame_processor
```

**kmsgrab usage (DRM-based, better for GPU pipelines).**

```bash
# Capture using DRM, hardware-accelerate with VAAPI
ffmpeg -device /dev/dri/card0 -f kmsgrab -i - \
    -vf 'hwmap=derive_device=vaapi,scale_vaapi=1920:1080:format=nv12' \
    -c:v h264_vaapi -y session.mp4
```

kmsgrab drops fewer frames than x11grab because it captures at the DRM level rather than through the X server. However, it requires:
- Access to `/dev/dri/card0` (DRM device permissions).
- A DRM-capable GPU (even virtual GPUs like virtio-gpu work).
- Root or appropriate group membership (`video` group).

**avfoundation usage (macOS).**

```bash
# List available capture devices
ffmpeg -f avfoundation -list_devices true -i ""

# Capture screen at 30fps
ffmpeg -f avfoundation -framerate 30 -i "1:none" \
    -c:v libx264 -preset fast -crf 20 \
    -y session.mp4

# Capture with hardware encoding (VideoToolbox)
ffmpeg -f avfoundation -framerate 30 -i "1:none" \
    -c:v h264_videotoolbox -b:v 5M \
    -y session.mp4
```

**gdigrab usage (Windows).**

```bash
# Capture the entire desktop
ffmpeg -f gdigrab -framerate 10 -i desktop \
    -c:v libx264 -preset ultrafast \
    -y session.mp4

# Capture a specific window by title
ffmpeg -f gdigrab -framerate 10 -i title="Calculator" \
    -c:v libx264 -preset ultrafast \
    -y session.mp4
```

**Headless capture from Xvfb / virtual displays.**

For CUA gateways running desktop runtimes in containers, the typical pattern is:

```bash
# Start Xvfb with a specific display number and resolution
Xvfb :99 -screen 0 1920x1080x24 &

# Set the display for applications
export DISPLAY=:99

# Launch the target application
firefox &

# Start recording
ffmpeg -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -c:v libx264 -preset ultrafast -crf 23 \
    -y /evidence/session.mp4 &

# Capture individual frames on demand (per-action evidence)
ffmpeg -f x11grab -video_size 1920x1080 -i :99 \
    -frames:v 1 -y /evidence/frames/pre_action_001.png
```

**CUA-specific FFmpeg considerations.**

| Consideration | Detail |
|---------------|--------|
| Frame rate for evidence | 5-10 fps is typically sufficient for action evidence; higher rates waste storage without improving auditability |
| On-demand screenshots | For per-action pre/post evidence, use `-frames:v 1` to capture single frames rather than continuous recording |
| Lossless screenshots | Use PNG (`-f image2 -c:v png`) for evidence frames that will be hashed; lossy compression changes hashes |
| Video for audit | Use H.264/H.265 for continuous session video intended for human review |
| Pipe output | Stream frames via pipe for real-time hash computation without disk I/O |
| Timestamps | Use `-copyts` and `-start_at_zero` to preserve accurate timing |

---

### Apple ScreenCaptureKit

**What it is.** ScreenCaptureKit is Apple's high-performance framework for capturing screen content on macOS. Introduced at WWDC 2022 (macOS 12.3+), it provides fine-grained control over what to capture (specific windows, applications, or entire displays) with minimal performance overhead.

**Core components.**

| Component | Purpose |
|-----------|---------|
| `SCShareableContent` | Discovers available screens, windows, and applications that can be captured |
| `SCContentFilter` | Specifies what to capture: a single window, an application, a display, or exclusions |
| `SCStreamConfiguration` | Configures capture parameters: resolution, frame rate, pixel format, color space, cursor visibility, audio |
| `SCStream` | The capture session itself; start/stop capture, receive frames via delegate |
| `CMSampleBuffer` | Individual captured frames delivered to the delegate callback |

**Capture flow.**

```swift
import ScreenCaptureKit

// 1. Discover available content
let content = try await SCShareableContent.current

// 2. Find the target window or display
let display = content.displays.first!
let targetWindow = content.windows.first { $0.title == "Firefox" }

// 3. Create a content filter
let filter: SCContentFilter
if let window = targetWindow {
    // Capture a specific window
    filter = SCContentFilter(desktopIndependentWindow: window)
} else {
    // Capture the entire display
    filter = SCContentFilter(display: display,
                             excludingWindows: [])
}

// 4. Configure the stream
let config = SCStreamConfiguration()
config.width = 1920
config.height = 1080
config.minimumFrameInterval = CMTime(value: 1, timescale: 10) // 10 fps
config.pixelFormat = kCVPixelFormatType_32BGRA
config.showsCursor = true
config.capturesAudio = false

// 5. Create and start the stream
let stream = SCStream(filter: filter,
                      configuration: config,
                      delegate: self)
try stream.addStreamOutput(self,
                            type: .screen,
                            sampleHandlerQueue: captureQueue)
try await stream.startCapture()
```

**Processing captured frames.**

```swift
extension CaptureEngine: SCStreamOutput {
    func stream(_ stream: SCStream,
                didOutputSampleBuffer sampleBuffer: CMSampleBuffer,
                of type: SCStreamOutputType) {

        guard type == .screen,
              sampleBuffer.isValid else { return }

        // Get the pixel buffer
        guard let pixelBuffer = sampleBuffer.imageBuffer else { return }

        // Get timing information
        let timestamp = sampleBuffer.presentationTimeStamp

        // Convert to CGImage for hashing/saving
        let ciImage = CIImage(cvPixelBuffer: pixelBuffer)
        let context = CIContext()
        guard let cgImage = context.createCGImage(ciImage,
                                                   from: ciImage.extent) else { return }

        // Hash the frame for evidence
        let pngData = cgImage.pngData()
        let hash = SHA256.hash(data: pngData)

        // Save if needed
        try? pngData.write(to: frameURL)
    }
}
```

**Permission model.**

- ScreenCaptureKit requires the user to grant **Screen Recording** permission.
- Permission is managed in **System Settings > Privacy & Security > Screen Recording**.
- The choice is stored per-application (by bundle identifier).
- The first capture attempt triggers a system permission prompt.
- Sandboxed apps can request Screen Recording permission (unlike Accessibility).
- On macOS Sequoia (15), Apple may require re-authorization after system updates.

**Window/app-specific capture.** ScreenCaptureKit's key advantage for CUA is the ability to capture specific windows or applications, which:

- Reduces capture of sensitive content from other applications.
- Supports data minimization (only capture what's relevant).
- Enables per-window evidence without full desktop capture.

**Rust bindings.** The `screencapturekit-rs` crate provides Rust bindings for ScreenCaptureKit, relevant for integrating with the Clawdstrike Rust codebase:

```rust
use screencapturekit::sc_stream::SCStream;
use screencapturekit::sc_content_filter::SCContentFilter;
use screencapturekit::sc_stream_configuration::SCStreamConfiguration;
```

---

### Windows Desktop Duplication API

**What it is.** The Desktop Duplication API (part of DXGI 1.2+) provides the most efficient way to capture the Windows desktop. It exposes the current desktop frame as a Direct3D texture, making it ideal for GPU-accelerated processing pipelines.

**Core interface: `IDXGIOutputDuplication`.**

| Method | Purpose |
|--------|---------|
| `AcquireNextFrame(timeout, &frameInfo, &resource)` | Acquires the next desktop frame; blocks until a new frame is available or timeout expires |
| `ReleaseFrame()` | Releases the acquired frame back to the system |
| `GetFrameDirtyRects(&buffer, bufferSize, &rectsSize)` | Returns non-overlapping rectangles indicating regions updated since the last frame |
| `GetFrameMoveRects(&buffer, bufferSize, &rectsSize)` | Returns regions that were moved (e.g., scrolling) since the last frame |
| `MapDesktopSurface(&mappedRect)` | Maps the desktop surface for CPU access (only for certain configurations) |

**Initialization flow.**

```cpp
#include <dxgi1_2.h>
#include <d3d11.h>

// 1. Create D3D11 device
ID3D11Device *device = nullptr;
ID3D11DeviceContext *context = nullptr;
D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
    0, nullptr, 0, D3D11_SDK_VERSION,
    &device, nullptr, &context);

// 2. Get DXGI adapter and output
IDXGIDevice *dxgiDevice = nullptr;
device->QueryInterface(&dxgiDevice);

IDXGIAdapter *adapter = nullptr;
dxgiDevice->GetAdapter(&adapter);

IDXGIOutput *output = nullptr;
adapter->EnumOutputs(0, &output);

IDXGIOutput1 *output1 = nullptr;
output->QueryInterface(&output1);

// 3. Create the duplication
IDXGIOutputDuplication *duplication = nullptr;
output1->DuplicateOutput(device, &duplication);
```

**Frame acquisition loop.**

```cpp
DXGI_OUTDUPL_FRAME_INFO frameInfo;
IDXGIResource *resource = nullptr;

while (running) {
    // Acquire next frame (100ms timeout)
    HRESULT hr = duplication->AcquireNextFrame(100, &frameInfo, &resource);

    if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
        continue;  // No new frame yet
    }

    if (SUCCEEDED(hr)) {
        // Get the frame as a D3D11 texture
        ID3D11Texture2D *texture = nullptr;
        resource->QueryInterface(&texture);

        // Process dirty rects (what changed)
        UINT dirtyRectsSize = 0;
        duplication->GetFrameDirtyRects(nullptr, 0, &dirtyRectsSize);
        if (dirtyRectsSize > 0) {
            std::vector<RECT> dirtyRects(dirtyRectsSize / sizeof(RECT));
            duplication->GetFrameDirtyRects(
                dirtyRects.data(),
                dirtyRectsSize,
                &dirtyRectsSize
            );
            // Process changed regions...
        }

        // Process move rects (what scrolled/moved)
        UINT moveRectsSize = 0;
        duplication->GetFrameMoveRects(nullptr, 0, &moveRectsSize);
        if (moveRectsSize > 0) {
            std::vector<DXGI_OUTDUPL_MOVE_RECT> moveRects(
                moveRectsSize / sizeof(DXGI_OUTDUPL_MOVE_RECT)
            );
            duplication->GetFrameMoveRects(
                moveRects.data(),
                moveRectsSize,
                &moveRectsSize
            );
            // Process moved regions...
        }

        // Copy texture for evidence capture
        // (copy to staging texture, map, read pixels, hash)

        texture->Release();
        resource->Release();
        duplication->ReleaseFrame();
    }
}
```

**Key characteristics.**

| Property | Detail |
|----------|--------|
| Frame format | Always `DXGI_FORMAT_B8G8R8A8_UNORM` regardless of display mode |
| Dirty rects | Non-overlapping rectangles of changed regions; avoids full-frame comparison |
| Move rects | Regions that moved (source point + destination rect); efficient for scroll detection |
| D3D11 integration | Frames are D3D11 textures; can be processed on GPU without CPU readback |
| Privilege requirements | Must run in the same session as the desktop; cannot capture across sessions |
| Failure recovery | Duplication interface can become invalid (e.g., mode switch, DRM content); must re-create |

**Value for CUA receipts.** The dirty rects and move rects are particularly valuable for CUA evidence:

- They provide a system-level ground truth of what changed on screen.
- They can be used to validate that the agent's action had the expected visual effect.
- They reduce the need for full-frame perceptual hashing (only hash changed regions).
- They can be included in receipts as `evidence.diff.changed_regions`.

---

### PipeWire + XDG ScreenCast Portal

**What it is.** On modern Linux desktops with Wayland, screen capture is mediated through the XDG Desktop Portal `ScreenCast` interface. The portal grants access to a PipeWire stream that delivers screen frames. PipeWire is a low-latency multimedia framework that handles audio/video routing on modern Linux.

**Session creation flow.**

```
1. CreateSession(options) -> session_handle
   Create a new ScreenCast session via D-Bus.

2. SelectSources(session_handle, options)
   Options:
   - types: MONITOR (1) | WINDOW (2) | VIRTUAL (4)
   - multiple: allow selecting multiple sources
   - cursor_mode: HIDDEN (1) | EMBEDDED (2) | METADATA (4)
   - persist_mode: do not persist (0) | permissions persist (1) | until revoked (2)

3. Start(session_handle, parent_window, options) -> streams
   User consent prompt appears (unless headless/auto-granted).
   Returns array of PipeWire stream descriptors:
   - node_id: PipeWire node ID to connect to
   - properties: stream metadata (size, source_type)
```

**Consuming the PipeWire stream.**

```c
#include <pipewire/pipewire.h>
#include <spa/param/video/format-utils.h>

// Connect to the PipeWire stream using the node_id from the portal
struct pw_stream *stream = pw_stream_new(core, "CUA Capture",
    pw_properties_new(
        PW_KEY_MEDIA_TYPE, "Video",
        PW_KEY_MEDIA_CATEGORY, "Capture",
        NULL
    ));

// Define the format we want
struct spa_pod_builder b = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
const struct spa_pod *params[1];
params[0] = spa_pod_builder_add_object(&b,
    SPA_TYPE_OBJECT_Format,  SPA_PARAM_EnumFormat,
    SPA_FORMAT_mediaType,    SPA_POD_Id(SPA_MEDIA_TYPE_video),
    SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
    SPA_FORMAT_VIDEO_format, SPA_POD_Id(SPA_VIDEO_FORMAT_BGRx),
    SPA_FORMAT_VIDEO_size,   SPA_POD_Rectangle(&SPA_RECTANGLE(1920, 1080)),
    NULL);

// Connect with the portal-provided node_id
pw_stream_connect(stream,
    PW_DIRECTION_INPUT,
    portal_node_id,
    PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
    params, 1);
```

**Processing frames from PipeWire.**

```c
static void on_process(void *data) {
    struct pw_buffer *pw_buf = pw_stream_dequeue_buffer(stream);
    if (!pw_buf) return;

    struct spa_buffer *buf = pw_buf->buffer;
    struct spa_data *d = &buf->datas[0];

    // Access the frame data
    void *frame_data = d->data;
    size_t frame_size = d->chunk->size;
    int stride = d->chunk->stride;

    // Get metadata (header with timestamps)
    struct spa_meta_header *header = spa_buffer_find_meta_data(
        buf, SPA_META_Header, sizeof(*header));
    if (header) {
        int64_t timestamp_ns = header->pts;
        // Use for receipt timing
    }

    // Hash the frame for evidence
    // SHA256(frame_data, frame_size) -> frame_hash

    pw_stream_queue_buffer(stream, pw_buf);
}
```

**Portal access control and permissions.**

PipeWire's portal integration provides a layered permission model:

1. **Portal daemon** maintains an unrestricted connection to PipeWire (identified by `pipewire.access.portal.is_portal = true`).
2. When a client requests screen capture, the portal:
   - Identifies which PipeWire nodes the client needs.
   - Creates a new restricted connection for the client.
   - Passes the restricted file descriptor to the client.
3. The client can only access nodes that the portal explicitly permitted.
4. PipeWire checks permissions of all parent nodes as well, preventing privilege escalation through node hierarchy traversal.

**Metadata available in PipeWire buffers.**

| Metadata type | Content | CUA relevance |
|--------------|---------|---------------|
| `SPA_META_Header` | Timestamps (pts), flags (corrupt buffer) | Timing for receipt events |
| `SPA_META_VideoDamage` | Regions that changed since last frame | Efficient diff computation |
| `SPA_META_Cursor` | Cursor position and bitmap | Include in evidence |
| `SPA_META_Control` | Stream control changes | Detect configuration changes |

**Practical considerations.**

| Consideration | Detail |
|---------------|--------|
| Mandatory metadata | `SPA_META_Header` is mandatory; flags.corrupt is mandatory; timestamps are optional but strongly recommended |
| DMA-BUF support | PipeWire can deliver frames as DMA-BUFs for zero-copy GPU processing |
| Latency | PipeWire emphasizes very low latency; typical frame delivery is sub-millisecond after compositor renders |
| Distro variance | Behavior varies by desktop session type and distro; avoid assuming uniform behavior |
| Headless operation | In headless compositors (Weston, etc.), the ScreenCast portal can auto-grant without user prompt |

---

## Browser Capture Technologies

### CDP Page.captureScreenshot

**What it is.** The Chrome DevTools Protocol provides `Page.captureScreenshot` for capturing the rendered content of a browser page. This is the primary evidence capture mechanism for browser-first CUA deployments.

**Command parameters.**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | string | `"png"` | Image format: `"jpeg"`, `"png"`, or `"webp"` |
| `quality` | integer | - | Compression quality 0-100 (JPEG/WebP only) |
| `clip` | object | - | Capture a specific region: `{x, y, width, height, scale}` |
| `fromSurface` | boolean | `true` | Capture from the surface rather than the view |
| `captureBeyondViewport` | boolean | `false` | Capture content beyond the visible viewport |
| `optimizeForSpeed` | boolean | `false` | Optimize encoding speed over output size |

**Return value.**

```json
{
    "data": "base64-encoded-image-data"
}
```

**Usage examples.**

```javascript
// Simple viewport screenshot (PNG)
const { data } = await cdpSession.send('Page.captureScreenshot', {
    format: 'png'
});
const buffer = Buffer.from(data, 'base64');
fs.writeFileSync('screenshot.png', buffer);

// Full-page screenshot
const metrics = await cdpSession.send('Page.getLayoutMetrics');
const { data: fullPage } = await cdpSession.send('Page.captureScreenshot', {
    format: 'png',
    captureBeyondViewport: true,
    clip: {
        x: 0,
        y: 0,
        width: metrics.cssContentSize.width,
        height: metrics.cssContentSize.height,
        scale: 1
    }
});

// Specific region capture
const { data: region } = await cdpSession.send('Page.captureScreenshot', {
    format: 'png',
    clip: {
        x: 100,
        y: 200,
        width: 400,
        height: 300,
        scale: 1
    }
});

// Fast JPEG for continuous monitoring
const { data: fast } = await cdpSession.send('Page.captureScreenshot', {
    format: 'jpeg',
    quality: 70,
    optimizeForSpeed: true
});
```

**Playwright integration for CUA evidence.**

```typescript
// Per-action evidence capture with Playwright
const page = await browser.newPage();

// Pre-action screenshot
const preScreenshot = await page.screenshot({ type: 'png', fullPage: false });
const preHash = crypto.createHash('sha256').update(preScreenshot).digest('hex');

// Perform the action
await page.click('#submit-button');

// Post-action screenshot (wait for rendering)
await page.waitForLoadState('networkidle');
const postScreenshot = await page.screenshot({ type: 'png', fullPage: false });
const postHash = crypto.createHash('sha256').update(postScreenshot).digest('hex');

// Build evidence for receipt
const evidence = {
    pre: { frame_hash: `sha256:${preHash}`, artifact_ref: 'pre_001.png' },
    post: { frame_hash: `sha256:${postHash}`, artifact_ref: 'post_001.png' },
};
```

**Timing considerations.**

| Concern | Mitigation |
|---------|-----------|
| Screenshot before paint completes | Wait for `requestAnimationFrame` or use `Page.lifecycleEvent` to ensure rendering is done |
| Dynamic content still loading | Use `Page.loadEventFired` or `Network.loadingFinished` to wait for resources |
| Animation in progress | Optionally disable CSS animations via `Emulation.setDocumentCookieDisabled` or inject CSS |
| Async UI updates | Wait for specific DOM mutations using `Runtime.evaluate` with MutationObserver |

**CDP socket security.** The CDP WebSocket endpoint must be protected:

- Never expose CDP on a public network (default is `localhost` only).
- Use a CDP proxy (chromedp-proxy) to log and filter CDP messages.
- Restrict which CDP domains/methods are available to the agent.
- Treat captured screenshots as sensitive data; enforce redaction before persistence.

---

### W3C Screen Capture API

**What it is.** The Screen Capture API extends the Media Capture and Streams specification to allow web applications to capture the contents of a display, window, or browser tab as a `MediaStream`. It uses `navigator.mediaDevices.getDisplayMedia()` as the entry point.

**Core API.**

```javascript
// Request screen capture (triggers user consent prompt)
const stream = await navigator.mediaDevices.getDisplayMedia({
    video: {
        cursor: 'always',          // 'always' | 'motion' | 'never'
        displaySurface: 'monitor', // 'monitor' | 'window' | 'browser'
        width: { ideal: 1920 },
        height: { ideal: 1080 },
        frameRate: { ideal: 10, max: 30 }
    },
    audio: false
});
```

**Recording with MediaRecorder.**

```javascript
const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });

const recorder = new MediaRecorder(stream, {
    mimeType: 'video/webm;codecs=vp9',
    videoBitsPerSecond: 2500000
});

const chunks = [];
recorder.ondataavailable = (event) => {
    if (event.data.size > 0) {
        chunks.push(event.data);
    }
};

recorder.onstop = () => {
    const blob = new Blob(chunks, { type: 'video/webm' });
    // Save or process the recording
};

recorder.start(1000); // Collect data every 1 second
```

**Capturing individual frames.**

```javascript
const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
const track = stream.getVideoTracks()[0];

// Use ImageCapture API for individual frames
const imageCapture = new ImageCapture(track);
const frame = await imageCapture.grabFrame();  // Returns ImageBitmap

// Draw to canvas for hashing
const canvas = document.createElement('canvas');
canvas.width = frame.width;
canvas.height = frame.height;
const ctx = canvas.getContext('2d');
ctx.drawImage(frame, 0, 0);

// Get as blob for hashing
canvas.toBlob(async (blob) => {
    const buffer = await blob.arrayBuffer();
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    // Use hash in receipt
}, 'image/png');
```

**Constraints and limitations.**

| Constraint | Detail |
|-----------|--------|
| User consent required | `getDisplayMedia()` always prompts the user; permission cannot be persisted (each call requires new consent) |
| Must be triggered by user gesture | Cannot be called programmatically without a preceding user interaction |
| No silent capture | Browser UI always indicates active capture (red border, icon) |
| Limited control | Cannot specify exact window/display programmatically; user chooses |
| Browser support | Supported in Chrome, Firefox, Safari, Edge; implementation details vary |

**Constraints for getDisplayMedia.**

| Constraint | Values | Description |
|-----------|--------|-------------|
| `cursor` | `always`, `motion`, `never` | Whether to include the cursor |
| `displaySurface` | `monitor`, `window`, `browser` | Preferred capture surface type |
| `preferCurrentTab` | boolean | Request capture of the current tab (Chrome/Edge/Opera) |
| `systemAudio` | `include`, `exclude` | System audio capture (limited support) |
| `surfaceSwitching` | `include`, `exclude` | Allow switching capture source |

**Relevance for CUA.** The Screen Capture API is primarily useful for:

- WebRTC-based remote desktop streaming (the capture source for a CUA gateway web client).
- Lightweight capture clients that run in a browser.
- Not suitable as the primary evidence capture mechanism (too many user consent requirements, no programmatic control).

---

## Protocol-Level Recording

### Guacamole Session Recording

**What it is.** Apache Guacamole's session recording captures the Guacamole protocol stream rather than raw video. This produces compact protocol dumps that can be played back in-browser or converted to video using the `guacenc` tool. Since v1.5.0, Guacamole supports direct in-browser playback of recordings.

**How it works.**

```
User/Agent session
    |
    v
guacd (Guacamole daemon)
    |
    +-- RDP/VNC/SSH protocol to target
    |
    +-- Guacamole protocol dump to disk
        |
        v
    /recordings/session_YYYY-MM-DD_HHMMSS.guac
```

**Configuring recording.** In `guacamole.properties` or per-connection settings:

```properties
# Enable recording for a VNC connection
recording-path=/var/guacamole/recordings
recording-name=session-${GUAC_DATE}-${GUAC_TIME}
recording-exclude-output=false
recording-exclude-mouse=false
recording-include-keys=true
create-recording-path=true
```

**Storage characteristics.**

| Metric | Value |
|--------|-------|
| Size per minute | ~1 MB for typical Guacamole protocol dump |
| Conversion overhead | `guacenc` converts 1 MB dump to ~10 MB MPEG-4 video |
| Storage efficiency | 10-100x smaller than raw video recording (protocol-level, not pixel-level) |

**guacenc conversion tool.**

```bash
# Convert protocol dump to video (default 640x480, 2 Mbps)
guacenc recording.guac

# Custom resolution and bitrate
guacenc -s 1920x1080 -r 5000000 recording.guac

# Output is recording.m4v (MPEG-4)
```

**In-browser playback (v1.5.0+).**

The `guacamole-history-recording-storage` extension allows the web application to find recordings on disk and play them back directly in the browser interface, without converting to video first. This provides:

- Immediate playback without conversion delay.
- Native protocol-level fidelity (no transcoding artifacts).
- Searchable key events (v1.6.0 adds key event display similar to `guaclog`).

**Key event recording.** Guacamole can record key events separately, and the `guaclog` utility converts these to a human-readable format. Version 1.6.0 integrates this into the web playback interface, allowing reviewers to see both the visual session and the key sequence.

**Value for CUA receipts.**

| Advantage | Detail |
|-----------|--------|
| Protocol-level fidelity | Records exactly what was sent/received through the remote desktop protocol |
| Compact storage | 10-100x smaller than raw video; ideal for long-running sessions |
| No transcoding for playback | Can be played back directly in browser |
| Searchable events | Key events and timestamps are structured, not embedded in video |
| Pairs with frame evidence | Use Guacamole recording for continuous audit + per-action frame captures for receipts |

**CUA integration pattern.** When Guacamole is the remote desktop gateway:

1. Enable protocol recording for all sessions.
2. For each agent action, additionally capture per-action screenshots via the RDP/VNC protocol.
3. Hash the per-action frames and include in receipts.
4. Reference the Guacamole recording by session ID and timestamp range in the receipt.
5. Store both protocol dumps and per-action frames in the artifact store.

---

## Video Encoding and Codecs

### Codec Selection

The choice of video codec for session recording affects storage cost, encoding CPU/GPU usage, playback compatibility, and forensic readability.

**Codec comparison for CUA session recording.**

| Codec | Compression Efficiency | Encoding Speed | Decode Support | Licensing | CUA Use Case |
|-------|----------------------|----------------|---------------|-----------|-------------|
| **H.264 (AVC)** | Good | Fast (excellent hardware support) | Universal | Royalty-bearing (but free for most uses via x264/LGPL) | Default for session video; universal playback |
| **H.265 (HEVC)** | ~30-40% better than H.264 | Slower encoding | Broad but not universal | Complex licensing; MPEG-LA + others | Use when storage is premium and playback is controlled |
| **VP9** | Comparable to H.265 | Slower than H.264 | Good (browsers, Android) | Royalty-free (BSD license) | Good for web playback pipelines |
| **AV1** | ~30% better than H.265 | Slowest (CPU); fast with hardware | Growing (Chrome, Firefox, modern GPUs) | Royalty-free (BSD license) | Future-proof; use when hardware encoding available |
| **VP8** | Worse than H.264 | Fast | Good (WebRTC) | Royalty-free | Legacy; avoid for new systems |

**Recommended codec strategy for CUA.**

| Artifact type | Recommended codec | Rationale |
|--------------|-------------------|-----------|
| Per-action screenshots | PNG (lossless) | Exact pixel integrity for hashing; no compression artifacts |
| Continuous session video | H.264 (libx264 or hardware) | Universal playback; good balance of size and quality |
| Archival/cold storage | AV1 (SVT-AV1 or hardware) | Best compression; transcode from H.264 when moving to cold tier |
| WebRTC streaming | VP8/VP9 or H.264 | Browser compatibility |

**FFmpeg encoding presets for CUA.**

```bash
# H.264 for session recording (fast, good quality)
ffmpeg -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -c:v libx264 -preset ultrafast -crf 23 -pix_fmt yuv420p \
    -y session.mp4

# H.264 for archival (better compression, slower)
ffmpeg -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -c:v libx264 -preset medium -crf 18 -pix_fmt yuv420p \
    -y session_archive.mp4

# H.265 for premium storage savings
ffmpeg -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -c:v libx265 -preset fast -crf 28 \
    -y session.mp4

# AV1 via SVT-AV1 (software, slower but royalty-free)
ffmpeg -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -c:v libsvtav1 -preset 8 -crf 30 \
    -y session.mkv

# Lossless PNG frames for evidence
ffmpeg -f x11grab -video_size 1920x1080 -i :99 \
    -frames:v 1 -c:v png -f image2 \
    -y frame_%04d.png
```

---

### GPU Acceleration

Hardware-accelerated encoding reduces CPU load and is important for CUA gateways that need to record while simultaneously running desktop applications.

**GPU acceleration options.**

| Accelerator | Platform | Codec support | FFmpeg encoder name | Notes |
|------------|----------|---------------|--------------------|----|
| **NVIDIA NVENC** | Linux/Windows (NVIDIA GPUs) | H.264, H.265, AV1 (RTX 40+) | `h264_nvenc`, `hevc_nvenc`, `av1_nvenc` | NVENC AV1 outperforms HEVC by 75-100% in speed |
| **Intel VAAPI** | Linux (Intel GPUs, gen7+) | H.264, H.265, AV1 (Arc) | `h264_vaapi`, `hevc_vaapi`, `av1_vaapi` | Works with both integrated and discrete Intel GPUs |
| **Intel QSV** | Linux/Windows (Intel GPUs) | H.264, H.265, AV1 (Arc) | `h264_qsv`, `hevc_qsv`, `av1_qsv` | Higher-level API than VAAPI; more features |
| **Apple VideoToolbox** | macOS (Apple Silicon, Intel) | H.264, H.265 | `h264_videotoolbox`, `hevc_videotoolbox` | Integrated into macOS; excellent quality/perf |
| **AMD AMF** | Linux/Windows (AMD GPUs) | H.264, H.265, AV1 (RX 7000+) | `h264_amf`, `hevc_amf`, `av1_amf` | AV1 support on Radeon RX 7000 series |

**NVENC usage example.**

```bash
# H.264 with NVIDIA hardware encoding
ffmpeg -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -c:v h264_nvenc -preset p4 -tune ll -b:v 5M \
    -y session.mp4

# AV1 with NVIDIA hardware encoding (RTX 40 series)
ffmpeg -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -c:v av1_nvenc -preset p4 -b:v 3M \
    -y session.mkv
```

**VAAPI usage example.**

```bash
# H.264 with Intel VAAPI
ffmpeg -vaapi_device /dev/dri/renderD128 \
    -f x11grab -r 10 -video_size 1920x1080 -i :99 \
    -vf 'format=nv12,hwupload' \
    -c:v h264_vaapi -b:v 5M \
    -y session.mp4
```

**GPU acceleration in containers.** For CUA gateways running in containers:

```bash
# NVIDIA GPU access in Docker
docker run --gpus all \
    --device /dev/dri/renderD128 \
    ...

# Intel GPU access
docker run --device /dev/dri/renderD128 \
    ...
```

---

### FFmpeg Licensing

FFmpeg's licensing is configuration-dependent and must be carefully managed:

**License tiers.**

| Configuration | License | Key constraints |
|--------------|---------|----------------|
| Default (no `--enable-gpl`) | LGPL v2.1+ | Can link dynamically from proprietary code; must provide LGPL source |
| `--enable-gpl` | GPL v2+ | Entire work becomes GPL if distributed; required for libx264, libx265 |
| `--enable-version3` | LGPL v3+ / GPL v3+ | Required for Apache 2.0 libraries (VMAF, mbedTLS, OpenCORE) |
| `--enable-nonfree` | Non-distributable | For proprietary codecs; cannot be distributed |

**Component licensing implications.**

| Component | License | Requires `--enable-gpl`? |
|-----------|---------|------------------------|
| FFmpeg core | LGPL v2.1+ | No |
| libx264 (H.264 encoder) | GPL v2+ | Yes |
| libx265 (HEVC encoder) | GPL v2+ | Yes |
| libsvtav1 (AV1 encoder) | BSD-2-Clause | No |
| libvpx (VP8/VP9) | BSD-3-Clause | No |
| Hardware encoders (NVENC, VAAPI, QSV) | Vendor SDK terms | Varies; typically no GPL needed |

**CUA gateway licensing strategy.**

- For the core gateway (which may be proprietary or Apache-2.0), prefer:
  - LGPL-only FFmpeg build (no `--enable-gpl`).
  - Use hardware encoders (NVENC, VAAPI, VideoToolbox) which don't trigger GPL.
  - Use libsvtav1 or libvpx for software encoding (both permissively licensed).
- If libx264/libx265 are needed, run FFmpeg as an external process rather than linking it into the gateway binary. This may preserve LGPL compliance for the gateway itself (consult legal counsel).
- Include capture-tool version and build configuration digests in receipt metadata for reproducibility.

---

## Frame Hashing

### Cryptographic Hashing (SHA-256)

**Purpose.** Cryptographic hashes provide **exact integrity verification** for captured frames. If even a single pixel changes, the hash is completely different. This is the foundation of the receipt evidence chain.

**Usage in CUA.**

```python
import hashlib
from PIL import Image
import io

def hash_frame(image_data: bytes) -> str:
    """SHA-256 hash of raw image bytes."""
    return f"sha256:{hashlib.sha256(image_data).hexdigest()}"

# Hash a PNG screenshot
with open("screenshot.png", "rb") as f:
    png_data = f.read()
frame_hash = hash_frame(png_data)
# -> "sha256:a3b1c2d4e5f6..."
```

```rust
use sha2::{Sha256, Digest};

fn hash_frame(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{:x}", hasher.finalize())
}
```

**Important considerations.**

| Consideration | Detail |
|---------------|--------|
| Format sensitivity | SHA-256 of a PNG and SHA-256 of a JPEG of the same image will be different; always hash the same format |
| Compression determinism | Some image encoders are non-deterministic (e.g., PNG with different compression levels, JPEG with different implementations); standardize the encoder |
| Metadata inclusion | Image metadata (EXIF, timestamps) affects the hash; strip metadata before hashing if you want pixel-only integrity |
| Performance | SHA-256 of a 1920x1080 PNG (~3-6 MB) takes ~1-5ms on modern hardware; negligible for per-action evidence |
| Storage | SHA-256 produces a 32-byte (64 hex character) hash; minimal storage overhead |

**Best practice for CUA.** Hash the raw PNG bytes of each evidence frame. Use PNG because it is lossless and deterministic (same pixels always produce the same PNG with the same encoder settings). Include the hash in the receipt's `evidence.pre.frame_hash` and `evidence.post.frame_hash` fields.

---

### Perceptual Hashing

**Purpose.** Perceptual hashes detect **visual similarity** across different encodings, resolutions, and minor modifications. Unlike SHA-256, which changes completely with any pixel modification, perceptual hashes produce similar values for visually similar images. This is useful for:

- Detecting whether two screenshots show "essentially the same content" despite compression differences.
- Identifying similar frames across sessions.
- Comparing pre/post action frames to estimate visual impact.
- Detecting near-duplicate screenshots in storage.

**Common algorithms.**

| Algorithm | Method | Hash size | Robustness | Speed |
|-----------|--------|-----------|-----------|-------|
| **aHash** (Average Hash) | Resize to 8x8, compare each pixel to mean luminance | 64 bits | Low (sensitive to color shifts) | Very fast |
| **dHash** (Difference Hash) | Resize to 9x8, compare adjacent pixel luminance | 64 or 128 bits | Good (robust against color/brightness changes) | Very fast |
| **pHash** (Perceptual Hash) | DCT of grayscale image, threshold median frequency | 64 bits | High (robust against minor edits, compression) | Fast |
| **wHash** (Wavelet Hash) | Wavelet transform of grayscale image | 64 bits | High | Fast |
| **Blockhash** | Divide image into blocks, compare block means | Variable | Good | Fast |
| **ColourHash** | HSV color distribution fingerprint | Variable | Good for color-based matching | Fast |

**Python implementation using `imagehash`.**

```python
from PIL import Image
import imagehash

img = Image.open("screenshot.png")

# Compute various hashes
ahash = imagehash.average_hash(img)       # aHash
dhash = imagehash.dhash(img)              # dHash (row)
dhash_col = imagehash.dhash_vertical(img) # dHash (column)
phash = imagehash.phash(img)              # pHash
whash = imagehash.whash(img)              # wHash

# Compare two images
img1 = Image.open("pre_action.png")
img2 = Image.open("post_action.png")

hash1 = imagehash.phash(img1)
hash2 = imagehash.phash(img2)

# Hamming distance: 0 = identical, higher = more different
distance = hash1 - hash2
print(f"Perceptual distance: {distance}")

# Threshold for "same content"
if distance <= 5:
    print("Images are visually similar")
elif distance <= 15:
    print("Images have moderate differences")
else:
    print("Images are substantially different")
```

**Comparison thresholds (128-bit dHash).**

| Hamming distance | Interpretation |
|-----------------|----------------|
| 0-2 | Near-identical (compression artifacts only) |
| 3-10 | Minor visual differences (small UI changes) |
| 11-25 | Moderate differences (significant content change) |
| 26+ | Substantially different images |

**Usage in CUA receipts.** Include perceptual hashes alongside SHA-256:

```json
{
    "evidence": {
        "pre": {
            "frame_hash": "sha256:abc123...",
            "frame_phash": "phash:0x3c3c3e7e7e3c3c00"
        },
        "post": {
            "frame_hash": "sha256:def456...",
            "frame_phash": "phash:0x3c3c3e7e7e3c3c08"
        }
    }
}
```

The perceptual hash enables:
- Quick similarity checks without retrieving the full frame.
- Approximate change detection even when exact bytes differ (e.g., JPEG re-encoding).
- Similarity-based search across session evidence.

---

## Diff Computation

### Pixel-Level Differencing

**What it is.** Pixel-level differencing computes the absolute difference between corresponding pixels in two images, producing a difference image that highlights changed regions.

**Implementation.**

```python
import numpy as np
from PIL import Image

def pixel_diff(img1_path: str, img2_path: str) -> tuple:
    """Compute pixel-level difference between two images."""
    img1 = np.array(Image.open(img1_path).convert('RGB'))
    img2 = np.array(Image.open(img2_path).convert('RGB'))

    # Absolute difference per channel
    diff = np.abs(img1.astype(int) - img2.astype(int)).astype(np.uint8)

    # Total change per pixel (sum across channels)
    change_magnitude = diff.sum(axis=2)

    # Threshold to binary change map
    threshold = 30  # pixels with > 30 total channel difference
    change_mask = (change_magnitude > threshold).astype(np.uint8) * 255

    # Calculate statistics
    total_pixels = change_magnitude.size
    changed_pixels = np.count_nonzero(change_mask)
    change_percentage = (changed_pixels / total_pixels) * 100

    return diff, change_mask, change_percentage
```

**Rust implementation.**

```rust
use image::{GenericImageView, Rgba};

fn pixel_diff(img1: &image::DynamicImage, img2: &image::DynamicImage)
    -> (Vec<(u32, u32)>, f64)
{
    let (w, h) = img1.dimensions();
    let mut changed = Vec::new();
    let threshold: u32 = 30;

    for y in 0..h {
        for x in 0..w {
            let p1 = img1.get_pixel(x, y);
            let p2 = img2.get_pixel(x, y);
            let diff: u32 = (0..3).map(|i| {
                (p1[i] as i32 - p2[i] as i32).unsigned_abs()
            }).sum();

            if diff > threshold {
                changed.push((x, y));
            }
        }
    }

    let total = (w * h) as f64;
    let pct = (changed.len() as f64 / total) * 100.0;
    (changed, pct)
}
```

**Limitations.**

- Sensitive to sub-pixel rendering differences, font antialiasing, and cursor blinking.
- Does not distinguish "meaningful" changes from noise.
- Binary threshold is fragile; too low captures noise, too high misses subtle changes.

---

### Region-Based Change Detection

**What it is.** Rather than comparing individual pixels, region-based detection divides the image into blocks or contiguous regions and identifies which regions changed. This produces structured change data suitable for receipt evidence.

**Bounding box extraction from change mask.**

```python
import numpy as np
from scipy import ndimage

def extract_changed_regions(change_mask: np.ndarray,
                            min_area: int = 100) -> list:
    """Extract bounding boxes of changed regions."""
    # Label connected components
    labeled, num_features = ndimage.label(change_mask)

    regions = []
    for i in range(1, num_features + 1):
        # Find bounding box of each component
        ys, xs = np.where(labeled == i)
        if len(ys) < min_area:
            continue  # Skip tiny noise regions

        x_min, x_max = xs.min(), xs.max()
        y_min, y_max = ys.min(), ys.max()

        regions.append({
            "x": int(x_min),
            "y": int(y_min),
            "w": int(x_max - x_min + 1),
            "h": int(y_max - y_min + 1),
            "pixel_count": int(len(ys))
        })

    return regions
```

**Windows Desktop Duplication dirty rects.** On Windows, the Desktop Duplication API provides dirty rects directly from the compositor, which is more accurate and efficient than pixel-level comparison:

```json
{
    "evidence": {
        "diff": {
            "source": "desktop_duplication_dirty_rects",
            "changed_regions": [
                { "x": 600, "y": 540, "w": 420, "h": 180 },
                { "x": 100, "y": 700, "w": 200, "h": 50 }
            ]
        }
    }
}
```

**PipeWire video damage metadata.** On Linux with PipeWire, `SPA_META_VideoDamage` provides similar region-based change information from the compositor.

---

### SSIM for Structural Similarity

**What it is.** The Structural Similarity Index Measure (SSIM) quantifies the perceived quality difference between two images by considering luminance, contrast, and structural information. Unlike pixel-level MSE, SSIM correlates well with human perception of image similarity.

**How SSIM works.**

SSIM computes three components using a sliding window (typically 11x11 Gaussian):

1. **Luminance comparison**: How similar are the mean luminance values?
2. **Contrast comparison**: How similar are the standard deviations?
3. **Structure comparison**: How similar are the normalized patterns?

The overall SSIM index combines these multiplicatively:

```
SSIM(x, y) = l(x,y) * c(x,y) * s(x,y)
```

**SSIM value interpretation.**

| SSIM value | Interpretation |
|-----------|----------------|
| 1.0 | Identical images |
| 0.95-0.99 | Nearly identical; compression artifacts only |
| 0.80-0.95 | Visible differences but same content structure |
| 0.50-0.80 | Significant structural changes |
| < 0.50 | Substantially different content |

**Implementation with scikit-image.**

```python
from skimage.metrics import structural_similarity as ssim
from skimage import io
import numpy as np

# Load pre and post action frames
img1 = io.imread("pre_action.png")
img2 = io.imread("post_action.png")

# Compute SSIM (returns global score and per-pixel SSIM map)
score, ssim_map = ssim(img1, img2,
                        multichannel=True,
                        full=True,
                        data_range=255)

print(f"SSIM score: {score:.4f}")

# Find regions with low SSIM (high change)
change_regions = (ssim_map < 0.8).astype(np.uint8) * 255
```

**Multi-Scale SSIM (MS-SSIM).** MS-SSIM extends SSIM by pooling similarity across multiple image scales:

- Better matches the human visual system's band-pass contrast sensitivity function.
- More robust for comparing images at different effective resolutions.
- Reduces high-frequency bias that can affect single-scale SSIM.

```python
# MS-SSIM implementation (conceptual)
def ms_ssim(img1, img2, levels=5):
    scores = []
    for level in range(levels):
        score = ssim(img1, img2)
        scores.append(score)
        # Downsample both images by 2x
        img1 = downsample(img1)
        img2 = downsample(img2)
    return np.prod(scores ** weights)
```

**Usage in CUA evidence.**

```json
{
    "evidence": {
        "diff": {
            "diff_hash": "sha256:...",
            "ssim_score": 0.87,
            "changed_regions": [
                { "x": 600, "y": 540, "w": 420, "h": 180, "local_ssim": 0.42 }
            ]
        }
    }
}
```

SSIM is valuable for CUA because:

- It provides a single score indicating "how much changed" that correlates with human perception.
- Low SSIM regions identify where meaningful changes occurred.
- It is robust against minor compression artifacts that would trip pixel-level comparison.
- It can be used as a trigger: if SSIM > 0.99, the action likely had no visible effect (possible injection failure).

---

## Receipt Evidence Pipeline

### Pipeline Architecture

The receipt evidence pipeline transforms raw screen captures into signed, hash-chained evidence. The pipeline executes for every agent action:

```
Agent requests action
    |
    v
1. PRE-ACTION CAPTURE
    +-- Capture screenshot (PNG, lossless)
    +-- Hash frame (SHA-256 + pHash)
    +-- Capture accessibility tree snapshot (hash)
    +-- Capture DOM snapshot if browser (hash)
    |
    v
2. EXECUTE ACTION
    +-- Inject input via chosen mechanism
    +-- Wait for rendering/settlement
    |
    v
3. POST-ACTION CAPTURE
    +-- Capture screenshot (PNG, lossless)
    +-- Hash frame (SHA-256 + pHash)
    +-- Capture accessibility tree snapshot (hash)
    +-- Capture DOM snapshot if browser (hash)
    |
    v
4. DIFF COMPUTATION
    +-- Pixel diff (changed regions)
    +-- SSIM score (structural similarity)
    +-- Perceptual hash distance
    +-- Hash the diff itself
    |
    v
5. RECEIPT EVENT CONSTRUCTION
    +-- Assemble evidence struct
    +-- Compute event hash (SHA-256 of canonical JSON)
    +-- Chain: event_hash = SHA-256(prev_event_hash || event_data)
    |
    v
6. SIGNING
    +-- Sign the receipt event (Ed25519 / COSE / JWS)
    +-- Key protected by TPM / Secure Enclave / TEE
    |
    v
7. STORAGE
    +-- Store signed receipt (append-only ledger)
    +-- Store artifacts (frames, diffs) to artifact store
    +-- Optionally publish receipt hash to transparency log
```

**Timing budget.** For interactive CUA sessions, the evidence pipeline should complete within the agent's action latency budget:

| Step | Target latency | Notes |
|------|---------------|-------|
| Pre-action screenshot | 10-50ms | Depends on capture method |
| SHA-256 hash | 1-5ms | ~3-6 MB PNG |
| pHash computation | 5-15ms | Requires resize + DCT |
| Action execution | Variable | Depends on action type |
| Post-action screenshot | 10-50ms | May need to wait for rendering |
| Diff computation (SSIM) | 20-100ms | Full-frame SSIM; region-only is faster |
| Receipt construction + signing | 1-10ms | Ed25519 is fast |
| Total overhead | ~50-250ms | Acceptable for most CUA use cases |

### Artifact Manifest and Signing

**Artifact manifest.** Define an artifact manifest that is itself signed (hash of hashes) and referenced by receipt metadata:

```json
{
    "manifest_version": "clawdstrike.artifact_manifest.v1",
    "session_id": "sess_01HXYZ...",
    "event_id": 42,
    "artifacts": [
        {
            "type": "pre_action_frame",
            "path": "frames/pre/000042.png",
            "sha256": "abc123...",
            "phash": "0x3c3c3e7e7e3c3c00",
            "size_bytes": 3145728,
            "dimensions": { "w": 1920, "h": 1080 },
            "format": "png",
            "captured_at": "2026-02-18T14:30:05.123Z"
        },
        {
            "type": "post_action_frame",
            "path": "frames/post/000042.png",
            "sha256": "def456...",
            "phash": "0x3c3c3e7e7e3c3c08",
            "size_bytes": 3200000,
            "dimensions": { "w": 1920, "h": 1080 },
            "format": "png",
            "captured_at": "2026-02-18T14:30:05.823Z"
        },
        {
            "type": "diff_map",
            "path": "diffs/000042.png",
            "sha256": "789ghi...",
            "size_bytes": 150000,
            "ssim_score": 0.87
        },
        {
            "type": "ax_tree_snapshot",
            "path": "a11y/000042.json",
            "sha256": "jkl012...",
            "size_bytes": 45000
        }
    ],
    "manifest_hash": "sha256:aggregate_hash_of_all_artifact_hashes",
    "capture_tool": {
        "name": "ffmpeg",
        "version": "7.1",
        "build_config_hash": "sha256:build_config_digest"
    }
}
```

**Signing the manifest.** The artifact manifest hash is included in the receipt event, which is then signed. This creates a chain:

```
Individual artifact hashes
    |
    v
Artifact manifest hash (SHA-256 of sorted artifact hashes)
    |
    v
Receipt event hash (includes manifest hash + prev_event_hash)
    |
    v
Signed receipt (Ed25519/COSE signature over event hash)
```

### Retention and Redaction

**Retention tiers.**

| Tier | Duration | Storage | Content |
|------|----------|---------|---------|
| `hot` | 7-30 days | Fast storage (SSD/object store) | Full artifacts: frames, diffs, video, accessibility snapshots |
| `warm` | 30-90 days | Standard storage | Compressed artifacts: H.265/AV1 video, downsampled frames |
| `cold` | 90-365 days | Archive storage (Glacier/etc.) | Receipts + manifest hashes only; artifacts deleted or redacted |
| `permanent` | Indefinite | Append-only ledger | Signed receipts and hash chain only |

**Policy-driven retention.** The retention tier should be configurable per-policy:

```yaml
# In policy configuration
evidence:
  retention:
    hot_days: 14
    warm_days: 60
    cold_days: 365
    redaction_on_cold: true
  artifacts:
    pre_post_frames: true
    continuous_video: false  # Only enable if needed
    accessibility_snapshots: true
    diff_maps: true
```

**Redaction pipeline.** Sensitive content must be removed before persistence. The pipeline ordering is critical:

```
1. DETECT sensitive regions
   +-- OCR scan for PII patterns (SSN, credit card, etc.)
   +-- Known sensitive UI regions (password fields)
   +-- DOM/accessibility analysis (input type="password")
   |
   v
2. MASK detected regions
   +-- Blur or black-fill rectangles
   +-- Record redaction metadata (reason, region, confidence)
   |
   v
3. HASH the redacted frame
   +-- SHA-256 of the post-redaction PNG
   +-- Note: this is the hash stored in the receipt, not the pre-redaction hash
   |
   v
4. SIGN the receipt
   +-- The receipt references the redacted frame hash
   +-- Redaction metadata is included in the evidence block
```

**Redaction evidence in receipts.**

```json
{
    "evidence": {
        "redactions": [
            {
                "kind": "blur_rect",
                "reason": "potential_pii",
                "confidence": 0.92,
                "rect": { "x": 120, "y": 220, "w": 540, "h": 60 },
                "detector": "ocr_pii_v2"
            },
            {
                "kind": "black_rect",
                "reason": "password_field",
                "confidence": 1.0,
                "rect": { "x": 300, "y": 400, "w": 200, "h": 30 },
                "detector": "dom_input_type"
            }
        ]
    }
}
```

**Important.** Distinguish "debug trace artifacts" (may contain unredacted content, short TTL, access-controlled) from "signed evidence artifacts" (redacted, hashed, referenced by receipts). Never mix these in the same storage path.

---

## Comparison Matrix

### Screen Capture Methods

| Method | Platform | Latency | CPU Usage | GPU Offload | Format Flexibility | Permission Model | CUA Suitability |
|--------|----------|---------|-----------|-------------|-------------------|-----------------|-----------------|
| **FFmpeg x11grab** | Linux (X11) | Low (~5-10ms/frame) | Medium | Yes (VAAPI, NVENC) | Any FFmpeg-supported | Display access only | Excellent for Xvfb containers |
| **FFmpeg kmsgrab** | Linux (DRM) | Very low | Low | Yes (DRM pipeline) | Any FFmpeg-supported | DRM device perms | Better than x11grab; needs GPU |
| **FFmpeg avfoundation** | macOS | Low | Medium | Yes (VideoToolbox) | Any FFmpeg-supported | Screen Recording perm | Good for macOS VMs |
| **FFmpeg gdigrab** | Windows | Medium | Medium | Limited | Any FFmpeg-supported | Session access | Acceptable; prefer DDUP |
| **ScreenCaptureKit** | macOS 12.3+ | Very low | Very low | Native | Raw pixel buffers | Screen Recording perm | Best for macOS |
| **Desktop Duplication** | Windows 8+ | Very low | Low | D3D11 native | Raw textures | Session access | Best for Windows |
| **PipeWire ScreenCast** | Linux (Wayland) | Very low | Low | DMA-BUF support | Raw pixel buffers | Portal-mediated | Best for Wayland |
| **CDP screenshot** | Browser (Chromium) | Low-Medium | Low | N/A | PNG/JPEG/WebP | CDP socket access | Best for browser-first |
| **W3C getDisplayMedia** | Browser | Medium | Medium | N/A | MediaStream (video) | User consent each time | Limited CUA use |
| **Guacamole recording** | Server-side | N/A (protocol level) | Very low | N/A | Protocol dump / M4V | Server config | Excellent for RD gateway |

### Frame Hashing Methods

| Method | Hash Size | Exact Integrity | Similarity Detection | Compression Robust | Speed | CUA Role |
|--------|-----------|----------------|---------------------|-------------------|-------|----------|
| **SHA-256** | 256 bits | Yes | No | No | ~1-5ms | Primary evidence integrity |
| **SHA-512** | 512 bits | Yes | No | No | ~2-8ms | Alternative when stronger hash needed |
| **aHash** | 64 bits | No | Yes (basic) | Moderate | <1ms | Quick similarity check |
| **dHash** | 64-128 bits | No | Yes (good) | Good | <1ms | Recommended perceptual hash |
| **pHash** | 64 bits | No | Yes (best) | High | ~5-15ms | High-quality similarity detection |
| **wHash** | 64 bits | No | Yes (good) | High | ~5-15ms | Alternative to pHash |
| **Blockhash** | Variable | No | Yes | Good | ~1-5ms | Grid-based alternative |

### Diff Methods

| Method | Output | Sensitivity | Semantic Meaning | Speed | CUA Role |
|--------|--------|------------|-----------------|-------|----------|
| **Pixel diff** | Change mask + percentage | Very high (noisy) | Low | Fast | Baseline change detection |
| **Region extraction** | Bounding boxes | Configurable (threshold) | Medium | Fast | Receipt `changed_regions` |
| **SSIM** | Score (0-1) + SSIM map | Perceptually calibrated | High | Medium (~20-100ms) | Quality metric for change magnitude |
| **MS-SSIM** | Score (0-1) | Better than SSIM at multiple scales | High | Slower | Archival quality assessment |
| **Dirty rects (DDUP)** | System-provided regions | Ground truth | High | Zero (compositor provides) | Best on Windows |
| **Video damage (PipeWire)** | Compositor-provided regions | Ground truth | High | Zero (compositor provides) | Best on Wayland |

### Encoding Profile Matrix

| Profile | Codec | Preset | CRF/Bitrate | CPU Cost | GPU Cost | File Size (1hr @ 10fps) | Use Case |
|---------|-------|--------|-------------|----------|----------|------------------------|----------|
| **Fast capture** | H.264 (libx264) | ultrafast | CRF 23 | Low | None | ~500 MB | Real-time session recording |
| **Balanced** | H.264 (libx264) | medium | CRF 20 | Medium | None | ~300 MB | Standard archival |
| **GPU fast** | H.264 (h264_nvenc) | p4 | 5 Mbps | None | Low | ~225 MB | GPU-equipped gateways |
| **Efficient** | H.265 (libx265) | fast | CRF 28 | Medium-High | None | ~200 MB | Storage-constrained |
| **GPU efficient** | H.265 (hevc_nvenc) | p4 | 3 Mbps | None | Low | ~135 MB | GPU + storage savings |
| **Maximum** | AV1 (libsvtav1) | preset 8 | CRF 30 | High | None | ~150 MB | Cold storage archival |
| **GPU max** | AV1 (av1_nvenc) | p4 | 2 Mbps | None | Low | ~90 MB | Best with RTX 40+ |
| **Lossless evidence** | PNG | N/A | N/A | Low | None | ~6 MB/frame | Per-action frame evidence |

---

## Implications for CUA Gateway Design

### Architecture Recommendations

1. **Separate debug traces from signed evidence.** Debug traces (full video, verbose logs) are useful during development but should never be confused with signed evidence artifacts. Evidence artifacts go through the redaction pipeline and are referenced by receipts.

2. **Use lossless PNG for per-action evidence frames.** These are the frames that get SHA-256 hashed and referenced in receipts. Lossy compression would make hashes unreproducible.

3. **Use lossy video for continuous session recording.** H.264 or H.265 for human-reviewable session replay. This is complementary to per-action evidence, not a replacement.

4. **Include both SHA-256 and perceptual hashes.** SHA-256 provides exact integrity. Perceptual hashes enable similarity search and approximate change detection without retrieving full frames.

5. **Leverage compositor-provided change metadata.** On Windows (dirty rects) and Wayland (video damage), the compositor knows exactly what changed. Use this instead of computing pixel diffs when available.

6. **Include capture tool metadata in receipts.** The FFmpeg version, build configuration, and encoder settings affect how frames are produced. Include these digests in the artifact manifest for reproducibility during incident review.

7. **Design the redaction pipeline as ordered stages.** Detect, mask, hash, sign -- in that order. The hash in the receipt references the post-redaction frame, and the redaction metadata documents what was removed and why.

8. **Plan for storage cost.** At 10 fps, a 1920x1080 session generates:
   - Per-action PNG evidence: ~6 MB per action (pre + post)
   - Continuous H.264 video: ~8 MB per minute (CRF 23, ultrafast)
   - Guacamole protocol dump: ~1 MB per minute
   - Design retention tiers (hot/warm/cold) with policy-driven movement.

9. **For the MVP, start with FFmpeg x11grab + CDP screenshots.**
   - FFmpeg x11grab for continuous session recording in Xvfb containers.
   - CDP `Page.captureScreenshot` for browser-first per-action evidence.
   - SHA-256 + pHash for all evidence frames.
   - SSIM for change magnitude assessment.
   - Guacamole recording if using Guacamole as the remote desktop gateway.

### Storage Cost Model

| Action rate | Per-action evidence (PNG) | Continuous video (H.264) | Protocol dump | Total per hour |
|-------------|--------------------------|--------------------------|---------------|----------------|
| 1 action/min | 360 MB/hr | 480 MB/hr | 60 MB/hr | ~900 MB/hr |
| 5 actions/min | 1.8 GB/hr | 480 MB/hr | 60 MB/hr | ~2.3 GB/hr |
| 10 actions/min | 3.6 GB/hr | 480 MB/hr | 60 MB/hr | ~4.1 GB/hr |

**Mitigation strategies:**
- Only capture per-action frames (skip continuous video) for lower-risk sessions.
- Use JPEG for pre-action frames and PNG only for post-action frames.
- Compress frames to WebP for warm storage.
- Transcode continuous video to AV1 for cold storage.

---

## References

### FFmpeg
- [FFmpeg Devices Documentation](https://www.ffmpeg.org/ffmpeg-devices.html)
- [FFmpeg Hardware/VAAPI wiki](https://trac.ffmpeg.org/wiki/Hardware/VAAPI)
- [FFmpeg AV1 Encoding Guide](https://trac.ffmpeg.org/wiki/Encode/AV1)
- [Hardware-Accelerated FFmpeg (NVENC, VAAPI, VideoToolbox)](https://www.ffmpeg.media/articles/hardware-accelerated-ffmpeg-nvenc-vaapi-videotoolbox)
- [FFmpeg License and Legal Considerations](https://www.ffmpeg.org/legal.html)
- [FFmpeg Licensing Compliance Guide (Hoop)](https://hoop.dev/blog/ffmpeg-licensing-compliance-avoiding-legal-pitfalls-in-your-build-process/)
- [kmsgrab Screen Capture](https://wiki.tonytascioglu.com/scripts/ffmpeg/kmsgrab_screen_capture)
- [NVIDIA NVENC AV1 in FFmpeg (Phoronix)](https://www.phoronix.com/news/NVIDIA-NVENC-AV1-FFmpeg)
- [NVIDIA FFmpeg GPU Guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.0/ffmpeg-with-nvidia-gpu/index.html)

### Apple ScreenCaptureKit
- [ScreenCaptureKit (Apple Developer)](https://developer.apple.com/documentation/screencapturekit/)
- [Capturing Screen Content in macOS (Apple Developer)](https://developer.apple.com/documentation/ScreenCaptureKit/capturing-screen-content-in-macos)
- [SCStream (Apple Developer)](https://developer.apple.com/documentation/screencapturekit/scstream)
- [SCStreamConfiguration (Apple Developer)](https://developer.apple.com/documentation/screencapturekit/scstreamconfiguration)
- [SCContentFilter (Apple Developer)](https://developer.apple.com/documentation/screencapturekit/sccontentfilter)
- [Meet ScreenCaptureKit (WWDC22)](https://developer.apple.com/videos/play/wwdc2022/10156/)
- [screencapturekit-rs (Rust bindings)](https://github.com/doom-fish/screencapturekit-rs)

### Windows Desktop Duplication API
- [Desktop Duplication API (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api)
- [IDXGIOutputDuplication (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nn-dxgi1_2-idxgioutputduplication)
- [AcquireNextFrame (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe)
- [GetFrameDirtyRects (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-getframedirtyrects)

### PipeWire + Portals
- [PipeWire Portal Access Control](https://docs.pipewire.org/page_portal.html)
- [XDG ScreenCast Portal Documentation](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.ScreenCast.html)
- [PipeWire (ArchWiki)](https://wiki.archlinux.org/title/PipeWire)

### CDP Screenshots
- [Chrome DevTools Protocol - Page Domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [CDP Page.captureScreenshot](https://chromedevtools.github.io/devtools-protocol/)
- [chromedp screenshot example (GitHub)](https://github.com/cyrus-and/chrome-remote-interface/wiki/Take-page-screenshot)

### W3C Screen Capture
- [Screen Capture W3C Specification](https://www.w3.org/TR/screen-capture/)
- [getDisplayMedia() (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getDisplayMedia)
- [Using the Screen Capture API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Screen_Capture_API/Using_Screen_Capture)
- [Screen Capture API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Screen_Capture_API)

### Guacamole Session Recording
- [Viewing Session Recordings in-browser (Guacamole Manual v1.6.0)](https://guacamole.apache.org/doc/gug/recording-playback.html)
- [Apache Guacamole Session Recordings (Medium)](https://theko2fi.medium.com/apache-guacamole-session-recordings-and-playback-in-browser-f095fcfca387)

### Frame Hashing
- [imagehash Python library (GitHub)](https://github.com/JohannesBuchner/imagehash)
- [imagehash (PyPI)](https://pypi.org/project/ImageHash/)
- [pHash.org](https://www.phash.org/)
- [Perceptual Hashing (Wikipedia)](https://en.wikipedia.org/wiki/Perceptual_hashing)
- [Duplicate Image Detection with Perceptual Hashing](https://benhoyt.com/writings/duplicate-image-detection/)

### SSIM and Image Comparison
- [Structural Similarity Index Measure (Wikipedia)](https://en.wikipedia.org/wiki/Structural_similarity_index_measure)
- [SSIM in scikit-image](https://scikit-image.org/docs/0.25.x/auto_examples/transform/plot_ssim.html)
- [SSIM (Imatest)](https://www.imatest.com/docs/ssim/)
- [MS-SSIM Overview (EmergentMind)](https://www.emergentmind.com/topics/multiscale-structural-similarity-score-ms-ssim)
