import React from 'react'
import { t } from '@/scripts/i18n'
import { Card } from '@oreui-web/react/card'
import { Container } from '@oreui-web/react/container'

const ViewerSkeleton: React.FC = () => (
  <Card {...({ className: 'user-card preview-card' } as any)}>
    <Container {...({ className: 'user-card-header', variant: 'light' } as any)}>
      <div className="d-flex justify-content-between w-100">
        <h2>
          <span>{t('general.texturePreview')}</span>
        </h2>
      </div>
    </Container>
    <div className="ore-card-body user-card-body"></div>
  </Card>
)

export default ViewerSkeleton
