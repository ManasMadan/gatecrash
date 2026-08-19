import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import '@gatecrash/ui/tokens.css'
import '@gatecrash/ui/verdict.css'
import '@/app.css'
import { App } from '@/App'

const root = document.getElementById('root')
if (!root) throw new Error('scanner: no root element')

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

/**
 * Keeps the screen awake while the scanner is open.
 *
 * A phone that sleeps between people is a phone somebody has to wake, unlock and
 * re-focus for every ticket, which at a busy gate is the difference between a queue
 * that moves and one that does not. The lock is re-acquired on visibility change
 * because the browser drops it when the tab is hidden.
 */
async function keepAwake(): Promise<void> {
  const wakeLock = (
    navigator as { wakeLock?: { request(kind: 'screen'): Promise<{ release(): Promise<void> }> } }
  ).wakeLock
  if (!wakeLock) return

  let sentinel: { release(): Promise<void> } | undefined
  const acquire = async () => {
    try {
      sentinel = await wakeLock.request('screen')
    } catch {
      // Denied, or the battery is too low. Nothing to do about it, and the scanner
      // still works.
    }
  }

  await acquire()
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && !sentinel) void acquire()
    if (document.visibilityState === 'hidden') sentinel = undefined
  })
}

void keepAwake()
