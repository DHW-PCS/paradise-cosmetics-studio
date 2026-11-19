import React, { useState, useRef, useEffect } from 'react'
import usePCSExtra from '@/scripts/hooks/usePCSExtra'
import useEmitMounted from '@/scripts/hooks/useEmitMounted'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { showModal } from '@/scripts/notify'
import urls from '@/scripts/urls'
import Alert from '@/components/Alert'
import AuthCard from '@/components/AuthCard'
import AuthField from '@/components/AuthField'
import Captcha from '@/components/Captcha'
import EmailSuggestion from '@/components/EmailSuggestion'
import { Button } from '@oreui-web/react/button'
import { Checkbox } from '@oreui-web/react/checkbox'
import { Container } from '@oreui-web/react/container'

type SuccessfulResponse = {
  code: 0
  message: string
  data: { redirectTo: string }
}
type FailedResponse = {
  code: number
  message: string
  data: { login_fails: number }
}
type Response = SuccessfulResponse | FailedResponse

function isSuccessfulResponse(
  response: Response,
): response is SuccessfulResponse {
  return response.code === 0
}

const Login: React.FC = () => {
  const [identification, setIdentification] = useState('')
  const [password, setPassword] = useState('')
  const [remember, setRemember] = useState(false)
  const [hasTooManyFails, setHasTooManyFails] = useState(false)
  const [isPending, setIsPending] = useState(false)
  const [warningMessage, setWarningMessage] = useState('')
  const ref = useRef<Captcha | null>(null)
  const recaptcha = usePCSExtra<string>('recaptcha')
  const invisibleRecaptcha = usePCSExtra<boolean>('invisible')

  useEmitMounted()

  useEffect(() => {
    setHasTooManyFails(pcs.extra.tooManyFails as boolean)
  }, [])

  const handleRememberChange = (event: Event) => {
    setRemember(
      (event.currentTarget as HTMLElement & { checked: boolean }).checked,
    )
  }

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setIsPending(true)

    const response = await fetch.post<Response>(urls.auth.login(), {
      identification,
      password,
      keep: remember,
      captcha: hasTooManyFails ? await ref.current!.execute() : undefined,
    })

    if (isSuccessfulResponse(response)) {
      window.location.href = response.data.redirectTo
    } else {
      setWarningMessage(response.message)
      setIsPending(false)
      ref.current?.reset()

      // only notify user if he/she fails too much at the first time
      if (response.data?.login_fails > 3 && !hasTooManyFails) {
        setHasTooManyFails(true)
        if (recaptcha) {
          // no need to notify if using invisible recaptcha
          if (!invisibleRecaptcha) {
            showModal({
              mode: 'alert',
              text: t('auth.tooManyFails.recaptcha'),
            })
          }
        } else {
          showModal({
            mode: 'alert',
            text: t('auth.tooManyFails.captcha'),
          })
        }
      }
    }
  }

  return (
    <AuthCard
      title={t('auth.login')}
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
          {isPending ? t('auth.loggingIn') : t('auth.login')}
        </Button>
      }
    >
      <EmailSuggestion
        type="text"
        placeholder={t('auth.identification')}
        required
        autoFocus
        value={identification}
        onChange={setIdentification}
      />
      <AuthField
        type="password"
        label={t('auth.password')}
        autoComplete="current-password"
        value={password}
        onChange={setPassword}
        required
      />
      {hasTooManyFails && <Captcha ref={ref} />}
      <Alert type="warning">{warningMessage}</Alert>
      <Container {...({ className: 'auth-option-container', variant: 'light' } as any)}>
        <div className="auth-options">
          <label className="auth-checkbox">
            <Checkbox
              {...({ checked: remember } as any)}
              onChange={handleRememberChange}
            />
            <span>{t('auth.keep')}</span>
          </label>
          <a className="auth-link" href={`${pcs.base_url}/auth/forgot`}>
            {t('auth.forgot-link')}
          </a>
        </div>
      </Container>
    </AuthCard>
  )
}

export default Login
