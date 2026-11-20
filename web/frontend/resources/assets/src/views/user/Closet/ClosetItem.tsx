import React, { useRef } from 'react'
import { t } from '@/scripts/i18n'
import type { ClosetItem as ClosetItemType } from '@/scripts/types'
import setAsAvatar from './setAsAvatar'
import { Card } from '@oreui-web/react/card'
import { Container } from '@oreui-web/react/container'
import { Dropdown } from '@oreui-web/react/dropdown'

interface Props {
  item: ClosetItemType
  selected: boolean
  onClick(item: ClosetItemType): void
  onRename(): void
  onRemove(): void
}

const ClosetItem: React.FC<Props> = (props) => {
  const { item } = props
  const dropdownRef = useRef<HTMLElement | null>(null)
  const preview = `${pcs.base_url}/preview/${item.tid}?height=150`
  const previewPNG = `${preview}&png`

  const closeMenu = () => {
    if (dropdownRef.current) {
      ;(dropdownRef.current as any).open = false
    }
  }

  const handleMediaClick = () => props.onClick(item)

  // keep card selection from firing when interacting with the menu
  const handleRename = (event: React.MouseEvent) => {
    event.stopPropagation()
    closeMenu()
    props.onRename()
  }

  const handleRemove = (event: React.MouseEvent) => {
    event.stopPropagation()
    closeMenu()
    props.onRemove()
  }

  const handleViewInSkinlib = (event: React.MouseEvent) => {
    event.stopPropagation()
    closeMenu()
  }

  const handleSetAsAvatar = (event: React.MouseEvent) => {
    event.stopPropagation()
    closeMenu()
    setAsAvatar(item.tid)
  }

  const handleTriggerClick = (event: React.MouseEvent) => {
    event.stopPropagation()
  }

  return (
    <Card
      {...({
        className: `skin-card closet-item-card${
          props.selected ? ' closet-item-selected' : ''
        }`,
      } as any)}
    >
      <div className="ore-card-media closet-item-media" onClick={handleMediaClick}>
        <picture>
          <source srcSet={preview} type="image/webp" />
          <img src={previewPNG} alt={item.pivot.item_name} />
        </picture>
        <Dropdown
          {...({
            className: 'ore-card-overlay-top-end closet-item-dropdown',
            ref: dropdownRef,
          } as any)}
        >
          <button
            className="ore-dropdown-trigger closet-item-trigger"
            type="button"
            onClick={handleTriggerClick}
          >
            <i className="fas fa-cog" aria-hidden="true"></i>
          </button>
          <div className="ore-dropdown-menu">
            <button className="ore-dropdown-item" onClick={handleRename}>
              {t('user.renameItem')}
            </button>
            <button className="ore-dropdown-item" onClick={handleRemove}>
              {t('user.removeItem')}
            </button>
            <a
              className="ore-dropdown-item"
              href={`${pcs.base_url}/skinlib/show/${item.tid}`}
              target="_blank"
              onClick={handleViewInSkinlib}
            >
              {t('user.viewInSkinlib')}
            </a>
            <button className="ore-dropdown-item" onClick={handleSetAsAvatar}>
              {t('user.setAsAvatar')}
            </button>
          </div>
        </Dropdown>
      </div>
      <div className="ore-card-body">
        <Container
          {...({ className: 'closet-item-caption', variant: 'light' } as any)}
        >
          <div className="ore-card-title" title={item.pivot.item_name}>
            {item.pivot.item_name}
          </div>
        </Container>
      </div>
    </Card>
  )
}

export default ClosetItem
