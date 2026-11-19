import * as React from 'react'
import { render } from './reactRoot'
import DarkModeButton from '@/components/DarkModeButton'

const el = document.querySelector('#toggle-dark-mode')
if (el) {
  const initMode = document.body.classList.contains('dark-mode')
  render(<DarkModeButton initMode={initMode} />, el)
}
