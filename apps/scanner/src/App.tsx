import { useCallback, useEffect, useState } from 'react'
import { Client } from '@gatecrash/protocol'
import { unlockAudio } from '@gatecrash/ui'

import { Enroll } from '@/Enroll'
import { Gate } from '@/Gate'
import { loadEnrollment, loadSettings, saveSettings, type Enrollment, type Settings } from '@/store'

/**
 * The scanner shell.
 *
 * Two states and no router: a device is either enrolled or it is not. Adding a
 * router would mean a bundle that fetches a chunk to show a screen, and at a gate
 * every request is a chance to fail. The whole app is one file's worth of state.
 */
export function App() {
  const [enrollment, setEnrollment] = useState<Enrollment | null>(() => loadEnrollment())
  const [settings, setSettings] = useState<Settings>(() => loadSettings())

  const updateSettings = useCallback((next: Settings) => {
    setSettings(next)
    saveSettings(next)
  }, [])

  // iOS suspends the audio context until a user gesture, and a scanner whose sounds
  // were silently dropped for the whole shift is a scanner staff stop trusting. One
  // listener on the first tap is all it takes.
  useEffect(() => {
    const unlock = () => {
      unlockAudio()
      window.removeEventListener('pointerdown', unlock)
    }
    window.addEventListener('pointerdown', unlock, { once: true })
    return () => window.removeEventListener('pointerdown', unlock)
  }, [])

  if (!enrollment) {
    return <Enroll onEnrolled={setEnrollment} />
  }

  return (
    <Gate
      enrollment={enrollment}
      settings={settings}
      onSettings={updateSettings}
      onSignedOut={() => setEnrollment(null)}
      onEnrollment={setEnrollment}
    />
  )
}

/**
 * Builds a client against a box URL without a token, for the enrollment call.
 *
 * Separate from the enrolled client because enrollment is the one request that is
 * unauthenticated: the single-use code in the body is the credential, and it arrived
 * on a printed sheet in the hands of somebody allowed to grant it.
 */
export function anonymousClient(boxUrl: string): Client {
  return new Client({ baseUrl: boxUrl })
}
