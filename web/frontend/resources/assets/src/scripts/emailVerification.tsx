import React from 'react'
import { render } from './reactRoot'
import EmailVerification from '@/views/widgets/EmailVerification'

const container = document.querySelector('#email-verification')

if (pcs.extra.unverified && container) {
  render(<EmailVerification />, container)
}
