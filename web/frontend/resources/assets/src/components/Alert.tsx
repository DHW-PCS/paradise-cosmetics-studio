import React from 'react'

type AlertType = 'success' | 'info' | 'warning' | 'danger'

const icons = new Map<AlertType, string>([
  ['success', 'check'],
  ['info', 'info'],
  ['warning', 'exclamation-triangle'],
  ['danger', 'times-circle'],
])

interface Props {
  type: AlertType
  children?: React.ReactNode
}

const Alert: React.FC<Props> = (props) => {
  const { type } = props
  const icon = icons.get(type)

  return props.children ? (
    <div
      className={`auth-message auth-message-${type}`}
      role={type === 'success' || type === 'info' ? 'status' : 'alert'}
    >
      <i className={`fas fa-${icon}`} aria-hidden="true"></i>
      <span>{props.children}</span>
    </div>
  ) : null
}

export default Alert
