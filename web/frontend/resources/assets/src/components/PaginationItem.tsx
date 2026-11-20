import React from 'react'
import { Button as OreButton } from '@oreui-web/react/button'

interface Props {
  children?: React.ReactNode
  disabled?: boolean
  active?: boolean
  // Prev/next items use the ore primary button; page numbers use the normal
  // (secondary) style. The active page stays secondary and is highlighted
  // through the .page-item.active CSS override (gray-60 face).
  primary?: boolean
  title?: string
  className?: string
  onClick?(): void
}

const PaginationItem: React.FC<Props> = (props) => {
  const classes = ['page-item']
  if (props.active) {
    classes.push('active')
  }
  if (props.disabled) {
    classes.push('disabled')
  }
  if (props.className) {
    classes.push(props.className)
  }

  const handleClick = (event: React.MouseEvent) => {
    event.preventDefault()
    if (!props.disabled && props.onClick) {
      props.onClick()
    }
  }

  const color = props.primary ? 'primary' : 'secondary'

  return (
    <li className={classes.join(' ')} title={props.title}>
      <OreButton
        {...({
          type: 'button',
          color,
          disabled: props.disabled,
          onClick: handleClick,
        } as any)}
      >
        {props.children}
      </OreButton>
    </li>
  )
}

export default PaginationItem
