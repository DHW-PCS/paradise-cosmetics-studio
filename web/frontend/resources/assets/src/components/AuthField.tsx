import React, { useEffect, useRef } from 'react'
import { Textfield } from '@oreui-web/react/textfield'

type Props = {
  autoComplete?: string
  autoFocus?: boolean
  className?: string
  label: string
  maxLength?: number
  minLength?: number
  name?: string
  onChange(value: string): void
  required?: boolean
  type: string
  value: string
}

const AuthField: React.FC<Props> = ({ autoFocus, onChange, ...props }) => {
  const ref = useRef<HTMLElement>(null)

  useEffect(() => {
    if (autoFocus) {
      ref.current?.querySelector('input')?.focus()
    }
  }, [autoFocus])

  const handleInput = (event: Event) => {
    onChange((event.currentTarget as HTMLElement & { value: string }).value)
  }

  return (
    <Textfield
      {...({
        ...props,
        ref,
        className: `auth-field ${props.className || ''}`.trim(),
      } as any)}
      onInput={handleInput}
    />
  )
}

export default AuthField
