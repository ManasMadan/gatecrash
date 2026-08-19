import type { Severity } from '@gatecrash/protocol'

/**
 * Sound and haptics for the gate.
 *
 * This exists because the screen is the least reliable channel a scanner has. A
 * bouncer at a busy door is watching the queue, not the phone; the phone is at hip
 * height, at an angle, possibly wet. What they actually operate on is the sound and
 * the buzz, and the screen is confirmation for the ambiguous cases.
 *
 * So the three verdict classes get three deliberately unmistakable signals:
 *
 * - admit    two rising notes, one short buzz. Over in 120ms so it never becomes
 *            the thing holding up the queue.
 * - deny     one low, harsh note, three long buzzes. Long enough to be felt
 *            through a jacket pocket and distinct from the admit buzz even when
 *            the sound is drowned out by a PA stack.
 * - redirect one flat mid note, two short buzzes. Neither of the other two, on
 *            purpose: "wrong door" must not feel like "forged ticket".
 *
 * Everything is synthesised with WebAudio rather than loaded as files. A sound file
 * is a network request, and at the moment this is needed there is no network. It is
 * also about 40 lines against several hundred kilobytes of audio.
 */

export interface FeedbackOptions {
  sound?: boolean
  haptics?: boolean
  /** 0 to 1. Gate staff turn this down; the default is loud because a gate is loud. */
  volume?: number
}

/** One note in a cue. */
interface Note {
  hz: number
  /** Seconds. */
  duration: number
  /** Seconds after the cue starts. */
  at: number
  type: OscillatorType
}

/**
 * The cues.
 *
 * The frequencies are chosen to sit above the low-frequency energy of a PA system
 * rather than to be pleasant. Around 900 Hz to 1.6 kHz is where a phone speaker is
 * loudest and where a bass-heavy room has the least masking.
 */
const CUES: Record<Severity, { notes: Note[]; vibrate: number[] }> = {
  admit: {
    notes: [
      { hz: 1050, duration: 0.05, at: 0, type: 'sine' },
      { hz: 1570, duration: 0.07, at: 0.05, type: 'sine' },
    ],
    vibrate: [35],
  },
  deny: {
    notes: [
      { hz: 220, duration: 0.16, at: 0, type: 'square' },
      { hz: 180, duration: 0.22, at: 0.16, type: 'square' },
    ],
    // Three long pulses. Felt through a jacket, and unmistakable against admit's
    // single short one.
    vibrate: [140, 70, 140, 70, 140],
  },
  redirect: {
    notes: [
      { hz: 780, duration: 0.09, at: 0, type: 'triangle' },
      { hz: 780, duration: 0.09, at: 0.14, type: 'triangle' },
    ],
    vibrate: [60, 60, 60],
  },
}

/**
 * Plays the cue for a verdict.
 *
 * Never throws and never awaits anything the caller cares about. A failed buzz
 * must not delay the verdict screen by a single frame, so every failure here is
 * swallowed: on iOS the audio context may be suspended until a user gesture, on
 * desktop there may be no vibration API, and in a headless test there is neither.
 */
export function playVerdict(severity: Severity, options: FeedbackOptions = {}): void {
  const { sound = true, haptics = true, volume = 0.9 } = options
  const cue = CUES[severity] ?? CUES.deny

  if (haptics) vibrate(cue.vibrate)
  if (sound) beep(cue.notes, volume)
}

/**
 * A distinct alarm cue, for an emergency incident arriving at a gate.
 *
 * Deliberately unlike any verdict: a rising two-tone repeated three times, which is
 * the shape every emergency signal in the world uses and which nobody will mistake
 * for a ticket being refused.
 */
export function playAlarm(options: FeedbackOptions = {}): void {
  const { sound = true, haptics = true, volume = 1 } = options
  if (haptics) vibrate([200, 100, 200, 100, 200, 100, 400])
  if (!sound) return

  const notes: Note[] = []
  for (let i = 0; i < 3; i++) {
    notes.push({ hz: 880, duration: 0.18, at: i * 0.4, type: 'square' })
    notes.push({ hz: 1320, duration: 0.18, at: i * 0.4 + 0.18, type: 'square' })
  }
  beep(notes, volume)
}

/** A quiet tick, for a scan that was accepted into the offline queue. */
export function playQueued(options: FeedbackOptions = {}): void {
  if (options.haptics !== false) vibrate([20])
  if (options.sound !== false)
    beep([{ hz: 1400, duration: 0.03, at: 0, type: 'sine' }], (options.volume ?? 0.9) * 0.4)
}

let context: AudioContext | undefined

/**
 * Returns the shared audio context, creating it lazily.
 *
 * Lazily and shared, because browsers cap the number of contexts a page may create
 * and because creating one before a user gesture leaves it suspended on iOS. The
 * scanner calls `unlockAudio` on its first tap to get past that.
 */
function audio(): AudioContext | undefined {
  if (typeof window === 'undefined') return undefined
  try {
    const Ctor =
      window.AudioContext ??
      (window as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
    if (!Ctor) return undefined
    context ??= new Ctor()
    return context
  } catch {
    return undefined
  }
}

/**
 * Resumes the audio context, which iOS requires from inside a user gesture.
 *
 * Called from the scanner's first tap. Without it, every sound is silently dropped
 * for the whole session and the first anybody knows is a bouncer saying the
 * scanner does not beep.
 */
export function unlockAudio(): void {
  const ctx = audio()
  if (ctx && ctx.state === 'suspended') void ctx.resume().catch(() => {})
}

function beep(notes: Note[], volume: number): void {
  const ctx = audio()
  if (!ctx) return

  try {
    const now = ctx.currentTime
    for (const note of notes) {
      const oscillator = ctx.createOscillator()
      const gain = ctx.createGain()
      oscillator.type = note.type
      oscillator.frequency.value = note.hz

      // A short attack and release. A square wave switched on instantaneously
      // clicks, and a click on every scan is the sound of a broken app.
      const start = now + note.at
      const end = start + note.duration
      gain.gain.setValueAtTime(0, start)
      gain.gain.linearRampToValueAtTime(Math.min(1, Math.max(0, volume)) * 0.3, start + 0.008)
      gain.gain.setValueAtTime(Math.min(1, Math.max(0, volume)) * 0.3, end - 0.02)
      gain.gain.linearRampToValueAtTime(0, end)

      oscillator.connect(gain).connect(ctx.destination)
      oscillator.start(start)
      oscillator.stop(end + 0.01)
    }
  } catch {
    // A gate does not stop working because the speaker did.
  }
}

function vibrate(pattern: number[]): void {
  try {
    // Absent on iOS Safari entirely, which is why the sound cue and the full-screen
    // colour both have to carry the signal on their own.
    navigator.vibrate?.(pattern)
  } catch {
    // Ignored.
  }
}

/** Exposed for tests: the cue table, so the patterns are assertable. */
export const cues = CUES
