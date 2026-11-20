import React, { useRef, useState } from 'react'
import { Modal as OreModal } from '@oreui-web/react/modal'
import { Container } from '@oreui-web/react/container'
import { Button } from '@oreui-web/react/button'
import { t } from '../scripts/i18n'
import ModalContent from './ModalContent'
import ModalInput from './ModalInput'
import type { Props as ContentProps } from './ModalContent'
import type {
  Props as InputProps,
  InternalProps as InputInternalProps,
} from './ModalInput'

type BasicOptions = {
  mode?: 'alert' | 'confirm' | 'prompt'
  show?: boolean
  input?: string
  validator?(value: any): string | boolean | undefined
  type?: string
  showHeader?: boolean
  center?: boolean
  children?: React.ReactNode
}

type FooterOptions = {
  title?: string
  okButtonText?: string
  okButtonType?: string
  cancelButtonText?: string
  cancelButtonType?: string
}

export type ModalOptions = BasicOptions &
  FooterOptions &
  ContentProps &
  InputProps

type Props = {
  id?: string
  footer?: React.ReactNode
  onConfirm?(payload: { value: string }): void
  onDismiss?(): void
  onClose?(): void
}

export type ModalResult = {
  value: string
}

// legacy bootstrap button classes used by callers, mapped to ore colors
const toOreColor = (type?: string): string | undefined => {
  if (!type) return undefined
  if (type.includes('danger')) return 'destructive'
  if (type === 'secondary' || type.includes('outline')) return 'secondary'
  return undefined
}

const Modal: React.FC<ModalOptions & Props> = (props) => {
  const {
    mode = 'confirm',
    title = t('general.tip'),
    text = '',
    input = '',
    placeholder = '',
    inputType = 'text',
    inputMode,
    showHeader = true,
    okButtonText = t('general.confirm'),
    okButtonType,
    cancelButtonText = t('general.cancel'),
    cancelButtonType,
  } = props

  const [value, setValue] = useState(input)
  const [valid, setValid] = useState(true)
  const [validatorMessage, setValidatorMessage] = useState('')
  const modalRef = useRef<HTMLElement>(null)

  const handleInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setValue(event.target.value)
  }

  const confirm = () => {
    const { validator } = props
    if (typeof validator === 'function') {
      const result = validator(value)
      if (typeof result === 'string') {
        setValidatorMessage(result)
        setValid(false)
        return
      }
    }

    ;(modalRef.current as any)?.close('confirm')
  }

  const dismiss = () => {
    ;(modalRef.current as any)?.close('dismiss')
  }

  const handleModalClose = (event: Event) => {
    const reason = (event as CustomEvent).detail?.reason as string
    if (reason === 'confirm') {
      props.onConfirm?.({ value })
    } else if (reason === 'dismiss') {
      props.onDismiss?.()
    }
    props.onClose?.()
  }

  const hasDefaultFooter = Boolean(
    props.footer || props.onConfirm || props.onDismiss,
  )

  return (
    <OreModal
      id={props.id}
      {...({
        className: 'global-modal',
        open: props.show ?? true,
        ref: modalRef,
        onModalClose: handleModalClose,
      } as any)}
    >
      <dialog className="ore-modal-dialog">
        <div className="ore-modal-content">
        {showHeader && (
          <div className="ore-modal-header">
            <h3 className="ore-modal-title">{title}</h3>
            <button
              type="button"
              className="ore-modal-header-button"
              aria-label={t('general.close')}
              onClick={dismiss}
            >
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
        )}
        <Container {...({ variant: 'dark' } as any)}>
          <ModalContent text={text} dangerousHTML={props.dangerousHTML}>
            {props.children}
          </ModalContent>
          {mode === 'prompt' && (
            <ModalInput
              inputType={inputType}
              inputMode={inputMode}
              choices={props.choices}
              placeholder={placeholder}
              value={value}
              invalid={!valid}
              validatorMessage={validatorMessage}
              onChange={handleInputChange}
            />
          )}
        </Container>
        {hasDefaultFooter && (
          <Container
            {...({ variant: 'light', className: 'global-modal-footer' } as any)}
          >
            {props.footer ?? (
              <>
                {mode !== 'alert' && props.onDismiss && (
                  <Button
                    {...({
                      color: toOreColor(cancelButtonType) ?? 'secondary',
                      onClick: dismiss,
                    } as any)}
                  >
                    {cancelButtonText}
                  </Button>
                )}
                <Button
                  {...({
                    color: toOreColor(okButtonType),
                    onClick: confirm,
                  } as any)}
                >
                  {okButtonText}
                </Button>
              </>
            )}
          </Container>
        )}
        </div>
      </dialog>
    </OreModal>
  )
}

export default Modal
