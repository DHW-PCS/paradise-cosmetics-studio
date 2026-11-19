import React, { useState, useRef } from 'react'
import useEmitMounted from '@/scripts/hooks/useEmitMounted'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import urls from '@/scripts/urls'
import Alert from '@/components/Alert'
import AuthCard from '@/components/AuthCard'
import Captcha from '@/components/Captcha'
import EmailSuggestion from '@/components/EmailSuggestion'
import { Button } from '@oreui-web/react/button'

const Forgot: React.FC = () => {
  const [email, setEmail] = useState('')
  const [isSending, setIsSending] = useState(false)
  const [successMessage, setSuccessMessage] = useState('')
  const [warningMessage, setWarningMessage] = useState('')
  const ref = useRef<Captcha | null>(null)

  useEmitMounted()

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setWarningMessage('')
    setIsSending(true)

    const captcha = await ref.current!.execute()
    const { code, message } = await fetch.post<fetch.ResponseBody>(
      urls.auth.forgot(),
      { email, captcha },
    )
    if (code === 0) {
      setSuccessMessage(message)
    } else {
      setWarningMessage(message)
      ref.current!.reset()
    }
    setIsSending(false)
  }

  return (
    <AuthCard
      title={t('auth.forgot-link')}
      onSubmit={handleSubmit}
      actions={
        <Button
          {...({
            className: 'auth-submit',
            type: 'submit',
            color: 'primary',
            loading: isSending,
            disabled: isSending,
          } as any)}
        >
          {isSending ? t('auth.sending') : t('auth.send')}
        </Button>
      }
    >
      <EmailSuggestion
        type="email"
        placeholder={t('auth.email')}
        required
        autoFocus
        value={email}
        onChange={setEmail}
      />
      <Captcha ref={ref} />
      <Alert type="success">{successMessage}</Alert>
      <Alert type="warning">{warningMessage}</Alert>
      <p className="auth-secondary-link">
        <a className="auth-link" href={`${pcs.base_url}/auth/login`}>
          {t('auth.forgot.login-link')}
        </a>
      </p>
    </AuthCard>
  )
}

export default Forgot
