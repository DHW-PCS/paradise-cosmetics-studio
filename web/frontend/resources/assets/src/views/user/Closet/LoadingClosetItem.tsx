import React from 'react'
import styled from '@emotion/styled'
import Skeleton from 'react-loading-skeleton'
import { Card } from '@oreui-web/react/card'
import { Container } from '@oreui-web/react/container'

const ItemNameSkeleton = styled(Skeleton)`
  width: 150px;
`

const LoadingClosetItem: React.FC = () => (
  <Card {...({ className: 'skin-card closet-item-card' } as any)}>
    <div className="ore-card-media closet-item-media">
      <span className="ore-card-overlay-top-end closet-item-trigger">
        <i className="fas fa-cog" aria-hidden="true"></i>
      </span>
    </div>
    <div className="ore-card-body">
      <Container
        {...({ className: 'closet-item-caption', variant: 'light' } as any)}
      >
        <div className="ore-card-title">
          <ItemNameSkeleton />
        </div>
      </Container>
    </div>
  </Card>
)

export default LoadingClosetItem
