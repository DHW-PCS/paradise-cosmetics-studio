import styled from '@emotion/styled'
import React from 'react'
import { Button } from '@oreui-web/react/button'
import { t } from '@/scripts/i18n'
import type { Line } from './types'

const Group = styled.td`
  width: 15%;
`
const Key = styled.td`
  width: 20%;
`
const Operations = styled.td`
  width: 25%;
`

interface Props {
  line: Line
  onEdit(line: Line): void
  onRemove(line: Line): void
}

const Row: React.FC<Props> = (props) => {
  const { line, onEdit, onRemove } = props
  const text = line.text[pcs.locale]

  const handleEditClick = () => onEdit(line)

  const handleRemoveClick = () => onRemove(line)

  return (
    <tr>
      <Group>{line.group}</Group>
      <Key>{line.key}</Key>
      <td>{text || t('admin.i18n.empty')}</td>
      <Operations>
        <Button
          {...({ color: 'secondary', className: 'mr-2', onClick: handleEditClick } as any)}
        >
          {t('admin.i18n.modify')}
        </Button>
        <Button
          {...({ color: 'destructive', onClick: handleRemoveClick } as any)}
        >
          {t('admin.i18n.delete')}
        </Button>
      </Operations>
    </tr>
  )
}

export default Row
