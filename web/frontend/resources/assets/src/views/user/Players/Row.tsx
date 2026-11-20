/** @jsxImportSource @emotion/react */
import { css } from '@emotion/react'
import { Button } from '@oreui-web/react/button'
import { t } from '@/scripts/i18n'
import type { Player } from '@/scripts/types'
import ButtonEdit from '@/components/ButtonEdit'
import * as cssUtils from '@/styles/utils'

interface Props {
  player: Player
  selected: boolean
  onClick: React.MouseEventHandler
  onEditName(player: Player): Promise<void>
  onReset(): void
  onDelete(player: Player): Promise<void>
}

const Row: React.FC<Props> = (props) => {
  const { player } = props

  const handleEdit = () => {
    props.onEditName(player)
  }

  const handleDelete = () => {
    props.onDelete(player)
  }

  const selected =
    props.selected &&
    css`
      background: #efefef;
      .dark-mode & {
        background: var(--dark);
      }
    `

  return (
    <tr css={[cssUtils.pointerCursor, selected]} onClick={props.onClick}>
      <td>{player.pid}</td>
      <td>
        <span>{player.name}</span>
        <ButtonEdit title={t('user.player.edit-pname')} onClick={handleEdit} />
      </td>
      <td className="d-flex">
        <Button {...({ color: 'secondary', onClick: props.onReset } as any)}>
          {t('user.player.delete-texture')}
        </Button>
        <Button
          {...({
            color: 'destructive',
            className: 'ml-2',
            onClick: handleDelete,
          } as any)}
        >
          {t('user.player.delete-player')}
        </Button>
      </td>
    </tr>
  )
}

export default Row
