import React, { useState, useEffect } from 'react'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { toast } from '@/scripts/notify'
import type { Player } from '@/scripts/types'
import urls from '@/scripts/urls'
import Loading from '@/components/Loading'
import Modal from '@/components/Modal'
import { Button } from '@oreui-web/react/button'
import { Textfield } from '@oreui-web/react/textfield'

const baseUrl = pcs.base_url

interface Props {
  show: boolean
  canAdd: boolean
  skin?: number
  cape?: number
  onClose(): void
}

const ModalApply: React.FC<Props> = (props) => {
  const [players, setPlayers] = useState<Player[]>([])
  const [search, setSearch] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    if (!props.show) {
      return
    }

    const getPlayers = async () => {
      setIsLoading(true)
      const players = await fetch.get<Player[]>(urls.user.player.list())
      setPlayers(players)
      setIsLoading(false)
    }
    getPlayers()
  }, [props.show])

  const handleSearch = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(event.target.value)
  }

  const handleSelect = async (player: Player) => {
    const { code, message } = await fetch.put<fetch.ResponseBody>(
      urls.user.player.set(player.pid),
      {
        skin: props.skin,
        cape: props.cape,
      },
    )
    if (code === 0) {
      toast.success(message)
      props.onClose()
    } else {
      toast.error(message)
    }
  }

  return (
    <Modal show={props.show} id="modal-apply" title={t('user.closet.use-as.title')} onClose={props.onClose}>
      {isLoading ? (
        <Loading />
      ) : players.length === 0 ? (
        <p>{t('user.closet.use-as.empty')}</p>
      ) : (
        <>
          <div className="form-group">
            <Textfield
              {...({
                type: 'text',
                placeholder: t('user.typeToSearch'),
                onInput: handleSearch,
              } as any)}
            />
          </div>
          {players
            .filter((player) => player.name.includes(search))
            .map((player) => (
              <Button
                key={player.pid}
                {...({
                  color: 'secondary',
                  className: 'apply-player-button',
                  title: player.name,
                  onClick: () => handleSelect(player),
                } as any)}
              >
                <picture>
                  <source
                    srcSet={`${baseUrl}/avatar/${player.tid_skin}?3d&size=45`}
                    type="image/webp"
                  />
                  <img
                    src={`${baseUrl}/avatar/${player.tid_skin}?3d&png&size=45`}
                    alt={player.name}
                    width={45}
                    height={45}
                  />
                </picture>
                <span className="ml-1">{player.name}</span>
              </Button>
            ))}
        </>
      )}
    </Modal>
  )
}

export default ModalApply
