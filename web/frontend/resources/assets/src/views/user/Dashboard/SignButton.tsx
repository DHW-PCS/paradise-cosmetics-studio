import React from 'react'
import { Button } from '@oreui-web/react/button'
import { t } from '@/scripts/i18n'
import * as scoreUtils from './scoreUtils'

interface Props {
  isLoading: boolean
  lastSign: Date
  canSignAfterZero: boolean
  signGap: number
  onClick: React.MouseEventHandler<HTMLElement>
}

const SignButton: React.FC<Props> = (props) => {
  const { lastSign, signGap, canSignAfterZero } = props
  const remainingTime = scoreUtils.remainingTime(
    lastSign,
    signGap,
    canSignAfterZero,
  )
  const remainingTimeText = scoreUtils.remainingTimeText(remainingTime)
  const canSign = remainingTime <= 0

  return (
    <Button
      {...({
        type: 'button',
        color: 'primary',
        disabled: !canSign || props.isLoading,
        onClick: props.onClick,
      } as any)}
    >
      <i className="far fa-calendar-check" aria-hidden="true" />{' '}
      {canSign ? t('user.sign') : remainingTimeText}
    </Button>
  )
}

export default React.memo(SignButton)
