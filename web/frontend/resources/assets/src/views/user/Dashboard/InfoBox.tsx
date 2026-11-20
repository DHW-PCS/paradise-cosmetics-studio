import React from 'react'
import { Container } from '@oreui-web/react/container'

interface Props {
  name: string
  icon: string
  color: string
  used: number
  unused: number
  unit: string
}

const InfoBox: React.FC<Props> = (props) => {
  const total = ~~(props.used + props.unused)
  const percentage = total > 0 ? (props.used / total) * 100 : 0

  return (
    <Container
      {...({
        className: `dashboard-info-box accent-${props.color}`,
        variant: 'dark',
      } as any)}
    >
      <div className="dashboard-info-box-heading">
        <i className={`fas fa-${props.icon}`} aria-hidden="true"></i>
        <span>{props.name}</span>
      </div>
      <div className="dashboard-info-box-number">
        <b>{props.used}</b> / {total} {props.unit}
      </div>
      <div
        className="dashboard-info-box-progress"
        role="progressbar"
        aria-valuenow={Math.round(percentage)}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <span style={{ width: `${percentage}%` }} />
      </div>
    </Container>
  )
}

export default React.memo(InfoBox)
