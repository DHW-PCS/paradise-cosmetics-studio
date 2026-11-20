import React, { useState } from 'react'
import { Textfield } from '@oreui-web/react/textfield'
import { t } from '@/scripts/i18n'
import Modal from '@/components/Modal'

interface Props {
  show: boolean
  onCreate(name: string, redirect: string): Promise<void>
  onClose(): void
}

const ModalCreate: React.FC<Props> = (props) => {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')

  const handleNameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setName(event.target.value)
  }

  const handleUrlChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setUrl(event.target.value)
  }

  const handleComplete = () => {
    props.onCreate(name, url)
  }

  const handleDismiss = () => {
    setName('')
    setUrl('')
  }

  return (
    <Modal
      show={props.show}
      onConfirm={handleComplete}
      onDismiss={handleDismiss}
      onClose={props.onClose}
    >
      <div className="form-group">
        <label htmlFor="new-app-name">{t('user.oauth.name')}</label>
        <Textfield
          {...({
            value: name,
            onInput: handleNameChange,
            type: 'text',
            required: true,
          } as any)}
        />
      </div>
      <div className="form-group">
        <label htmlFor="new-app-redirect">{t('user.oauth.redirect')}</label>
        <Textfield
          {...({
            value: url,
            onInput: handleUrlChange,
            type: 'url',
            required: true,
          } as any)}
        />
      </div>
    </Modal>
  )
}

export default ModalCreate
