import jsQR from 'jsqr'

/**
 * QR decoding from a camera frame.
 *
 * Two paths, and which one runs matters more than anything else in the scanner.
 *
 * `BarcodeDetector` is a native browser API available on Android Chrome, and it is
 * hardware-accelerated: it decodes a 1080p frame in single-digit milliseconds and
 * costs almost no battery. Where it exists, it is the whole reason a ₹6,000 phone
 * can hold a gate.
 *
 * jsQR is the fallback, in pure JavaScript, for iOS Safari and older Android. It is
 * roughly ten times slower, so the frame is downscaled before it runs — a 480-wide
 * grayscale frame decodes a QR held at arm's length perfectly well and is four
 * times less work than the full sensor.
 *
 * The published latency budget puts camera decode at 60 to 120ms, which is the
 * single largest term in scan-to-verdict. The network and the database are noise
 * next to it. That is why this file exists rather than a one-line library call.
 */

/** The native detector, when the browser has one. */
interface BarcodeDetectorLike {
  detect(source: CanvasImageSource): Promise<{ rawValue: string }[]>
}

interface BarcodeDetectorConstructor {
  new (options?: { formats?: string[] }): BarcodeDetectorLike
  getSupportedFormats?(): Promise<string[]>
}

/** Which decoder a scanner ended up with, shown on its diagnostics screen. */
export type DecoderKind = 'native' | 'javascript'

export interface Decoder {
  readonly kind: DecoderKind
  /** Returns the decoded string, or null when the frame holds no QR code. */
  decode(video: HTMLVideoElement): Promise<string | null>
}

/**
 * Builds the best decoder this browser can offer.
 *
 * Format-restricted to QR on purpose. Asking the native detector for every format
 * it knows makes it slower for no benefit, and it would also let a scanner
 * accidentally read the Code 128 barcode on somebody's lanyard.
 */
export async function createDecoder(): Promise<Decoder> {
  const Ctor = (globalThis as { BarcodeDetector?: BarcodeDetectorConstructor }).BarcodeDetector

  if (Ctor) {
    try {
      // Some browsers expose the constructor but support no formats, which is
      // worse than not having it: every detect() resolves empty and the scanner
      // silently never reads anything.
      const formats = (await Ctor.getSupportedFormats?.()) ?? ['qr_code']
      if (formats.includes('qr_code')) {
        return new NativeDecoder(new Ctor({ formats: ['qr_code'] }))
      }
    } catch {
      // Fall through to the JavaScript path.
    }
  }
  return new JavaScriptDecoder()
}

class NativeDecoder implements Decoder {
  readonly kind = 'native' as const

  constructor(private readonly detector: BarcodeDetectorLike) {}

  async decode(video: HTMLVideoElement): Promise<string | null> {
    try {
      // The video element is passed directly: the native path reads the frame
      // without a canvas round trip, which is most of where its speed comes from.
      const found = await this.detector.detect(video)
      return found[0]?.rawValue ?? null
    } catch {
      // A detect() failure mid-stream happens when the camera is being
      // reconfigured. Returning null lets the loop try the next frame rather than
      // tearing the scanner down.
      return null
    }
  }
}

class JavaScriptDecoder implements Decoder {
  readonly kind = 'javascript' as const

  private canvas: HTMLCanvasElement | undefined
  private context: CanvasRenderingContext2D | undefined

  /**
   * Width the frame is downscaled to before decoding.
   *
   * 480 is the smallest width at which a version 7 QR held at arm's length still
   * has enough pixels per module to decode reliably, and it is four times less
   * work than a 1080p frame. Going lower starts losing printed tickets, which are
   * denser than in-app codes.
   */
  private static readonly WIDTH = 480

  decode(video: HTMLVideoElement): Promise<string | null> {
    const source = this.grab(video)
    if (!source) return Promise.resolve(null)

    const found = jsQR(source.data, source.width, source.height, {
      // Both, because a phone screen shows a dark-on-light code and a printed
      // ticket photographed against a dark background can invert.
      inversionAttempts: 'attemptBoth',
    })
    return Promise.resolve(found?.data ?? null)
  }

  private grab(video: HTMLVideoElement): ImageData | null {
    const { videoWidth, videoHeight } = video
    if (videoWidth === 0 || videoHeight === 0) return null

    const width = Math.min(JavaScriptDecoder.WIDTH, videoWidth)
    const height = Math.round((width / videoWidth) * videoHeight)

    this.canvas ??= document.createElement('canvas')
    if (this.canvas.width !== width || this.canvas.height !== height) {
      this.canvas.width = width
      this.canvas.height = height
      this.context = undefined
    }
    // willReadFrequently tells the browser to keep the backing store in CPU
    // memory. Without it, every getImageData is a GPU readback, which on a mid
    // range phone costs more than the decode itself.
    this.context ??= this.canvas.getContext('2d', { willReadFrequently: true }) ?? undefined
    if (!this.context) return null

    this.context.drawImage(video, 0, 0, width, height)
    return this.context.getImageData(0, 0, width, height)
  }
}

/**
 * Opens the rear camera.
 *
 * Every constraint here is chosen against a specific failure seen at a gate:
 *
 * - `facingMode: environment` because the front camera is useless for this and is
 *   what a browser picks by default on some Android builds.
 * - A 1280 ideal width rather than the maximum: a 4K stream costs battery and
 *   thermal headroom and decodes no better, and a phone that thermally throttles
 *   halfway through doors is a gate that slows down.
 * - `focusMode: continuous` where supported, because a fixed-focus stream cannot
 *   read a ticket held closer than about 30cm and people hold tickets close.
 */
export async function openCamera(): Promise<MediaStream> {
  if (!navigator.mediaDevices?.getUserMedia) {
    // Almost always the secure-context rule: getUserMedia is unavailable over
    // plain HTTP, so a scanner served without the box's certificate has no camera.
    // Saying so is the difference between a five-minute fix and an hour.
    throw new Error(
      'This browser will not give the page a camera. Open the scanner over https and install the box certificate.',
    )
  }

  const stream = await navigator.mediaDevices.getUserMedia({
    video: {
      facingMode: { ideal: 'environment' },
      width: { ideal: 1280 },
      height: { ideal: 720 },
      frameRate: { ideal: 30 },
    },
    audio: false,
  })

  // Applied after the fact rather than as a constraint: an unsupported advanced
  // constraint makes the whole getUserMedia call fail, and losing the camera
  // because a phone does not support continuous focus would be absurd.
  const [track] = stream.getVideoTracks()
  if (track) {
    try {
      await track.applyConstraints({
        advanced: [{ focusMode: 'continuous' } as MediaTrackConstraintSet],
      })
    } catch {
      // Fixed focus. Still works, just needs the ticket held a little further away.
    }
  }
  return stream
}

/** Reports whether the camera's torch can be switched on. */
export function hasTorch(stream: MediaStream | undefined): boolean {
  const [track] = stream?.getVideoTracks() ?? []
  if (!track) return false
  const capabilities = track.getCapabilities?.() as { torch?: boolean } | undefined
  return capabilities?.torch === true
}

/**
 * Switches the torch on or off.
 *
 * Worth having its own control rather than relying on auto-exposure: a printed
 * ticket in a dark queue is the single most common thing a scanner cannot read,
 * and the fix is light.
 */
export async function setTorch(stream: MediaStream | undefined, on: boolean): Promise<void> {
  const [track] = stream?.getVideoTracks() ?? []
  if (!track) return
  try {
    await track.applyConstraints({ advanced: [{ torch: on } as MediaTrackConstraintSet] })
  } catch {
    // Not supported. The button is hidden in that case, so this is belt and braces.
  }
}
