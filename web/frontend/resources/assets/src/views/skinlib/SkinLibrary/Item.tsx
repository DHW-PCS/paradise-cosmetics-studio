import React from 'react'
import { t } from '@/scripts/i18n'
import { Card } from '@oreui-web/react/card'
import { Tag } from '@oreui-web/react/tag'
import type { LibraryItem } from './types'
import { humanizeType } from './utils'

interface Props {
  item: LibraryItem
  liked: boolean
  onAdd(texture: LibraryItem): Promise<void>
  onRemove(texture: LibraryItem): Promise<void>
  onUploaderClick(uploader: number): void
}

const Item: React.FC<Props> = (props) => {
  const { item } = props

  const link = `${pcs.base_url}/skinlib/show/${item.tid}`
  const preview = `${pcs.base_url}/preview/${item.tid}?height=150`
  const previewPNG = `${preview}&png`

  const handleUploaderClick = (event: React.MouseEvent) => {
    event.preventDefault()
    props.onUploaderClick(item.uploader)
  }

  const handleHeartClick = (event: React.MouseEvent) => {
    event.preventDefault()
    props.liked ? props.onRemove(item) : props.onAdd(item)
  }

  return (
    <div className="skin-item ml-3 mr-2 mb-2">
      <Card {...({ className: 'skin-card' } as any)}>
        <a
          className="ore-card-media"
          href={link}
          target="_blank"
          aria-label={item.name}
        >
          <picture>
            <source srcSet={preview} type="image/webp" />
            <img src={previewPNG} alt={item.name} />
          </picture>
          {item.public ? null : (
            <Tag
              {...({
                outlined: true,
                variant: 'notice',
                className: 'ore-card-overlay-top-start',
                title: t('skinlib.private'),
              } as any)}
            >
              <i className="fas fa-lock" aria-hidden="true"></i>
            </Tag>
          )}
          <div className="ore-card-overlay-bottom-start card-tag-group">
            <Tag {...({ outlined: true, variant: 'informative' } as any)}>
              {humanizeType(item.type)}
            </Tag>
          </div>
          <Tag
            {...({
              variant: 'neutral',
              className: 'ore-card-overlay-top-end skin-like',
              title: t('skinlib.show.likes'),
              onClick: handleHeartClick,
            } as any)}
          >
            <i
              className={`fas fa-heart ${props.liked ? 'skin-like-active' : ''}`}
              aria-hidden="true"
            ></i>
            {item.likes}
          </Tag>
        </a>
        <div className="ore-card-body">
          <div className="ore-card-caption">
            <div className="ore-card-title" title={item.name}>
              {item.name}
            </div>
          </div>
          <button
            className="ore-card-meta skin-uploader"
            title={t('skinlib.show.uploader')}
            onClick={() => props.onUploaderClick(item.uploader)}
          >
            {item.nickname}
          </button>
        </div>
      </Card>
    </div>
  )
}

export default Item
