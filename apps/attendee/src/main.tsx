import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import '@gatecrash/ui/tokens.css'
import '@gatecrash/ui/map.css'
import '@/app.css'
import { App } from '@/App'

const root = document.getElementById('root')
if (!root) throw new Error('attendee: no root element')

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
