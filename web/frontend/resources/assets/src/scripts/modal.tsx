import React from 'react'
import { render, unmountComponentAtNode } from './reactRoot'
import Modal, { ModalOptions, ModalResult } from '../components/Modal'

export function showModal(options: ModalOptions = {}): Promise<ModalResult> {
  return new Promise((resolve, reject) => {
    const container = document.createElement('div')
    document.body.appendChild(container)

    const handleClose = () => {
      unmountComponentAtNode(container)
      document.body.removeChild(container)
    }

    render(
      <Modal
        {...options}
        show
        center
        onConfirm={resolve}
        onDismiss={reject}
        onClose={handleClose}
      />,
      container,
    )
  })
}
