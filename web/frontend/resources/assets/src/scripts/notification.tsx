import React from 'react'
import { render } from './reactRoot'
import NotificationsList from '@/views/widgets/NotificationsList'

const container = document.querySelector('[data-notifications]')
if (container) {
  render(<NotificationsList />, container)
}
