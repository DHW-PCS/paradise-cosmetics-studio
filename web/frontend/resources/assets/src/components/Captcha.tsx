/** @jsxImportSource @emotion/react */
import * as React from 'react'
import Reaptcha from 'reaptcha'
import { emit, on } from '@/scripts/event'
import { t } from '@/scripts/i18n'
import { Textfield } from '@oreui-web/react/textfield'

const eventId = Symbol()

type State = {
  value: string
  time: number
  sitekey: string
  invisible: boolean
}

class Captcha extends React.Component<Record<string, unknown>, State> {
  state: State
  ref: React.MutableRefObject<Reaptcha | null>

  constructor(props: Record<string, unknown>) {
    super(props)
    this.state = {
      value: '',
      time: Date.now(),
      sitekey: pcs.extra.recaptcha,
      invisible: pcs.extra.invisible,
    }
    this.ref = React.createRef()
  }

  execute = async () => {
    const recaptcha = this.ref.current
    if (recaptcha && this.state.invisible) {
      return new Promise<string>((resolve) => {
        const off = on(eventId, (value: string) => {
          resolve(value)
          off()
        })
        recaptcha.execute()
      })
    }
    return this.state.value
  }

  reset = () => {
    const recaptcha = this.ref.current
    if (recaptcha) {
      recaptcha.reset()
    } else {
      this.setState({ time: Date.now() })
    }
  }

  handleValueChange = (event: Event) => {
    this.setState({
      value: (event.currentTarget as HTMLElement & { value: string }).value,
    })
  }

  handleVerify = (value: string) => {
    emit(eventId, value)
    this.setState({ value })
  }

  handleRefresh = () => {
    this.setState({ time: Date.now() })
  }

  render() {
    return this.state.sitekey ? (
      <div className="auth-captcha">
        <Reaptcha
          ref={this.ref}
          sitekey={this.state.sitekey}
          size={this.state.invisible ? 'invisible' : 'normal'}
          onVerify={this.handleVerify}
        />
      </div>
    ) : (
      <div className="auth-captcha auth-captcha-manual">
        <Textfield
          {...({
            className: 'auth-field',
            label: t('auth.captcha'),
            required: true,
            type: 'text',
            value: this.state.value,
          } as any)}
          onInput={this.handleValueChange}
        />
        <button
          className="auth-captcha-refresh"
          type="button"
          title={t('auth.change-captcha')}
          aria-label={t('auth.change-captcha')}
          onClick={this.handleRefresh}
        >
          <img
            src={`${pcs.base_url}/auth/captcha?v=${this.state.time}`}
            alt=""
            className="auth-captcha-image"
          />
        </button>
      </div>
    )
  }
}

export default Captcha
