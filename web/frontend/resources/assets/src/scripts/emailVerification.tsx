import React from 'react'
import ReactDOM from 'react-dom'
import EmailVerification from '@/views/widgets/EmailVerification'

const container = document.querySelector('#email-verification')

if (pcs.extra.unverified && container) {
  ReactDOM.render(<EmailVerification />, container)
}
