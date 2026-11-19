import React, { useState } from 'react'
import useEmitMounted from '@/scripts/hooks/useEmitMounted'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { toast } from '@/scripts/notify'
import urls from '@/scripts/urls'
import Alert from '@/components/Alert'
import AuthCard from '@/components/AuthCard'
import AuthField from '@/components/AuthField'
import { Button } from '@oreui-web/react/button'

const Reset: React.FC = () => {
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [warningMessage, setWarningMessage] = useState('')
  const [isPending, setIsPending] = useState(false)

  useEmitMounted()

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    if (password !== confirmation) {
      setWarningMessage(t('auth.invalidConfirmPwd'))
      return
    }

    setIsPending(true)
    const { code, message } = await fetch.post<fetch.ResponseBody>(
      location.href.replace(pcs.base_url, ''),
      { password },
    )
    if (code === 0) {
      toast.success(message)
      setTimeout(() => {
        window.location.href = pcs.base_url + urls.auth.login()
      }, 2000)
    } else {
      setWarningMessage(message)
      setIsPending(false)
    }
  }

  return (
    <AuthCard
      title={t('auth.reset')}
      onSubmit={handleSubmit}
      actions={
        <Button
          {...({
            className: 'auth-submit',
            type: 'submit',
            color: 'primary',
            loading: isPending,
            disabled: isPending,
          } as any)}
        >
          {isPending ? t('auth.resetting') : t('auth.reset')}
        </Button>
      }
    >
      <AuthField
        type="password"
        label={t('auth.password')}
        autoComplete="new-password"
        autoFocus
        minLength={8}
        maxLength={32}
        required
        value={password}
        onChange={setPassword}
      />
      <AuthField
        type="password"
        label={t('auth.repeat-pwd')}
        autoComplete="new-password"
        minLength={8}
        maxLength={32}
        required
        value={confirmation}
        onChange={setConfirmation}
      />
      <Alert type="warning">{warningMessage}</Alert>
      <p className="auth-secondary-link">
        <a className="auth-link" href={`${pcs.base_url}/auth/login`}>
          {t('auth.forgot.login-link')}
        </a>
      </p>
    </AuthCard>
  )
}

export default Reset
