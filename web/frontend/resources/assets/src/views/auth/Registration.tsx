import React, { useState, useRef } from 'react'
import usePCSExtra from '@/scripts/hooks/usePCSExtra'
import useEmitMounted from '@/scripts/hooks/useEmitMounted'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { toast } from '@/scripts/notify'
import urls from '@/scripts/urls'
import Alert from '@/components/Alert'
import AuthCard from '@/components/AuthCard'
import AuthField from '@/components/AuthField'
import Captcha from '@/components/Captcha'
import EmailSuggestion from '@/components/EmailSuggestion'
import { Button } from '@oreui-web/react/button'

// The invitation-codes field rides only the register request, unlike the
// original Svelte bootstrap that mutated every fetch payload globally.
interface InvitationField {
  label: string
}

const Registration: React.FC = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [nickName, setNickName] = useState('')
  const [playerName, setPlayerName] = useState('')
  const [invitationCode, setInvitationCode] = useState('')
  const [isPending, setIsPending] = useState(false)
  const [warningMessage, setWarningMessage] = useState('')
  const requirePlayer = usePCSExtra<boolean>('player')
  const invitation = usePCSExtra<InvitationField | null>('invitation', null)
  const captchaRef = useRef<Captcha | null>(null)

  useEmitMounted()

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setWarningMessage('')

    if (password !== confirmation) {
      setWarningMessage(t('auth.invalidConfirmPwd'))
      document.querySelector<HTMLInputElement>('.auth-confirmation input')?.focus()
      return
    }

    setIsPending(true)
    const { code, message } = await fetch.post<fetch.ResponseBody>(
      urls.auth.register(),
      Object.assign(
        { email, password, captcha: await captchaRef.current!.execute() },
        requirePlayer ? { player_name: playerName } : { nickname: nickName },
        invitation ? { invitationCode } : {},
      ),
    )
    if (code === 0) {
      toast.success(message)
      setTimeout(() => {
        window.location.href = `${pcs.base_url}/user`
      }, 3000)
    } else {
      setWarningMessage(message)
      captchaRef.current!.reset()
    }
    setIsPending(false)
  }

  return (
    <AuthCard
      title={t('auth.register')}
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
          {isPending ? t('auth.registering') : t('auth.register')}
        </Button>
      }
    >
      <EmailSuggestion
        type="email"
        required
        autoFocus
        placeholder={t('auth.email')}
        value={email}
        onChange={setEmail}
      />
      <AuthField
        type="password"
        label={t('auth.password')}
        autoComplete="new-password"
        minLength={8}
        maxLength={32}
        required
        value={password}
        onChange={setPassword}
      />
      <AuthField
        className="auth-confirmation"
        type="password"
        label={t('auth.repeat-pwd')}
        autoComplete="new-password"
        minLength={8}
        maxLength={32}
        required
        value={confirmation}
        onChange={setConfirmation}
      />
      {requirePlayer ? (
        <AuthField
          type="text"
          label={t('auth.player-name')}
          required
          value={playerName}
          onChange={setPlayerName}
        />
      ) : (
        <AuthField
          type="text"
          label={t('auth.nickname')}
          required
          value={nickName}
          onChange={setNickName}
        />
      )}
      {invitation && (
        <AuthField
          type="text"
          label={invitation.label}
          required
          value={invitationCode}
          onChange={setInvitationCode}
        />
      )}
      <Captcha ref={captchaRef} />
      <Alert type="warning">{warningMessage}</Alert>
      <p className="auth-secondary-link">
        <a className="auth-link" href={`${pcs.base_url}/auth/login`}>
          {t('auth.login-link')}
        </a>
      </p>
    </AuthCard>
  )
}

export default Registration
