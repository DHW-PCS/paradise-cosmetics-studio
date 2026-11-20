import React, { useState } from 'react'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { toast } from '@/scripts/notify'
import type { Player } from '@/scripts/types'
import urls from '@/scripts/urls'
import Modal from '@/components/Modal'
import { Textfield } from '@oreui-web/react/textfield'
import { Accordion } from '@oreui-web/react/accordion'
import { IconButton } from '@oreui-web/react/icon-button'
import { Container } from '@oreui-web/react/container'

type Extra = {
  score: number
  cost: number
  rule: string
  length: string
}

interface Props {
  show: boolean
  onAdd(player: Player): void
  onClose(): void
}

const ModalAddPlayer: React.FC<Props> = (props) => {
  const [name, setName] = useState('')
  const [noticeOpen, setNoticeOpen] = useState(true)

  const handleNameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setName(event.target.value)
  }

  const handleConfirm = async () => {
    const {
      code,
      message,
      data: player,
    } = await fetch.post<fetch.ResponseBody<Player>>(urls.user.player.add(), {
      name,
    })
    if (code === 0) {
      toast.success(message)
      props.onAdd(player)
    } else {
      toast.error(message)
    }
  }

  const handleClose = () => {
    setName('')
    props.onClose()
  }

  const { score, cost, rule, length } = pcs.extra as Extra
  const isScoreEnough = score >= cost

  return (
    <Modal
      show={props.show}
      title={t('user.player.add-player')}
      onConfirm={handleConfirm}
      onClose={handleClose}
    >
      <div className="form-group">
        <Textfield
          {...({
            type: 'text',
            label: t('general.player.player-name'),
            value: name,
            onInput: handleNameChange,
          } as any)}
        />
      </div>
      <Accordion
        {...({
          className: 'add-player-notice',
          open: noticeOpen,
          onOpenChange: (event: CustomEvent<boolean>) =>
            setNoticeOpen(event.detail),
        } as any)}
      >
        <IconButton
          {...({
            className: 'ore-accordion-trigger',
            type: 'button',
            'aria-label': t('general.notice'),
          } as any)}
        >
          <span className="ore-accordion-title">{t('general.notice')}</span>
        </IconButton>
        <div className="ore-accordion-content">
          <ul className="m-0 p-0 pl-3">
            <li {...({
              className: `add-player-score ${
                isScoreEnough ? 'is-enough' : 'is-not-enough'
              }`
            } as any)}>{t('user.cur-score')} {score}</li>
            <li>{rule}</li>
            <li>{length}</li>
          </ul>
        </div>
      </Accordion>
    </Modal>
  )
}

export default ModalAddPlayer
