import React, { useState, useEffect } from 'react'
import debounce from 'lodash.debounce'
import useEmitMounted from '@/scripts/hooks/useEmitMounted'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { showModal, toast } from '@/scripts/notify'
import {
  ClosetItem as Item,
  Texture,
  Paginator,
  TextureType,
} from '@/scripts/types'
import urls from '@/scripts/urls'
import { Button as OreButton } from '@oreui-web/react/button'
import { Card } from '@oreui-web/react/card'
import { Container } from '@oreui-web/react/container'
import { TabBar, TabButton } from '@oreui-web/react/tab-bar'
import { Textfield } from '@oreui-web/react/textfield'
import Pagination from '@/components/Pagination'
import ClosetItem from './ClosetItem'
import LoadingClosetItem from './LoadingClosetItem'
import Previewer from './Previewer'
import ModalApply from './ModalApply'
import removeClosetItem from './removeClosetItem'

type Category = 'skin' | 'cape'

// Items per page of the closet grid (200px cards wrap over two or three rows).
const CLOSET_PER_PAGE = 6

const updater = debounce(
  <T extends unknown>(
    value: React.SetStateAction<T>,
    setter: React.Dispatch<React.SetStateAction<T>>,
  ) => setter(value),
  350,
)

const Closet: React.FC = () => {
  const [isLoading, setIsLoading] = useState(true)
  const [category, setCategory] = useState<Category>('skin')
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [items, setItems] = useState<Item[]>([])
  const [skin, setSkin] = useState<Texture | null>(null)
  const [cape, setCape] = useState<Texture | null>(null)
  const [showModalApply, setShowModalApply] = useState(false)

  useEmitMounted()

  useEffect(() => {
    const getItems = async () => {
      setIsLoading(true)
      const { data, last_page } = await fetch.get<Paginator<Item>>(
        urls.user.closet.list(),
        { category, q: query, page, perPage: CLOSET_PER_PAGE },
      )

      setItems(data)
      setTotalPages(last_page)
      setIsLoading(false)
    }
    getItems()
  }, [category, query, page])

  const switchCategoryToSkin = () => {
    if (category !== 'skin') {
      setCategory('skin')
      setPage(1)
    }
  }

  const switchCategoryToCape = () => {
    if (category !== 'cape') {
      setCategory('cape')
      setPage(1)
    }
  }

  const handleSearch = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value
    setSearch(value)
    updater(value, setQuery)
  }

  const handlePageChange = (page: number) => setPage(page)

  const isSelected = (item: Item): boolean => {
    if (category === 'skin') {
      return item.tid === skin?.tid
    } else {
      return item.tid === cape?.tid
    }
  }

  const handleSelect = (item: Item) => {
    if (item.type === TextureType.Cape) {
      setCape(item)
    } else {
      setSkin(item)
    }
  }

  const resetSelected = () => {
    setSkin(null)
    setCape(null)
  }

  const renameItem = async (item: Item, index: number) => {
    let name: string
    try {
      const { value } = await showModal({
        mode: 'prompt',
        text: t('user.renameClosetItem'),
        input: item.pivot.item_name,
        validator: (value: string) => {
          if (!value) {
            return t('skinlib.emptyNewTextureName')
          }
        },
      })
      name = value
    } catch {
      return
    }

    const { code, message } = await fetch.put<fetch.ResponseBody>(
      urls.user.closet.rename(item.tid),
      { name },
    )
    if (code === 0) {
      toast.success(message)
      setItems((items) => {
        items[index] = { ...item, pivot: { ...item.pivot, item_name: name } }
        return items.slice()
      })
    } else {
      toast.error(message)
    }
  }

  const removeItem = async (item: Item) => {
    const { tid } = item
    const ok = await removeClosetItem(tid)
    if (ok) {
      setItems((items) => items.filter((item) => item.tid !== tid))
    }
  }

  const applyToPlayer = () => {
    if (!skin && !cape) {
      toast.info(t('user.emptySelectedTexture'))
      return
    }
    setShowModalApply(true)
  }

  return (
    <>
      <Card {...({ className: 'user-card closet-card' } as any)}>
        <Container {...({ className: 'user-card-header', variant: 'light' } as any)}>
          <div className="d-flex justify-content-between w-100">
            <TabBar>
              <TabButton
                {...({
                  palette: 'toggle',
                  selected: category === 'skin',
                  onChange: switchCategoryToSkin,
                } as any)}
              >
                {t('general.skin')}
              </TabButton>
              <TabButton
                {...({
                  palette: 'toggle',
                  selected: category === TextureType.Cape,
                  onChange: switchCategoryToCape,
                } as any)}
              >
                {t('general.cape')}
              </TabButton>
              <TabButton
                {...({
                  palette: 'toggle',
                  className: 'd-none d-md-inline-flex',
                  href: `${pcs.base_url}/skinlib/upload`,
                  onClick: (event: React.MouseEvent) => {
                    // lit-react 包装下 href 生成的内层链接未生效，这里显式跳转兜底；
                    // 保留 href 以支持中键打开等原生行为
                    const url = `${pcs.base_url}/skinlib/upload`
                    if (event.metaKey || event.ctrlKey) {
                      event.preventDefault()
                      window.open(url, '_blank')
                    } else if (
                      event.button === 0 &&
                      !event.shiftKey &&
                      !event.altKey
                    ) {
                      event.preventDefault()
                      window.location.assign(url)
                    }
                  },
                } as any)}
              >
                {t('user.closet.upload')}
              </TabButton>
            </TabBar>
            <Textfield
              {...({
                type: 'search',
                value: search,
                placeholder: t('user.typeToSearch'),
                'aria-label': t('user.typeToSearch'),
                onInput: handleSearch,
              } as any)}
            />
          </div>
        </Container>
        <div className="ore-card-body user-card-body">
          {isLoading ? (
            <div className="d-flex flex-wrap">
              {new Array(CLOSET_PER_PAGE).fill(null).map((_, i) => (
                <LoadingClosetItem key={i} />
              ))}
            </div>
          ) : items.length === 0 ? (
            <div className="text-center p-3">
              {search ? (
                t('general.noResult')
              ) : (
                <span
                  dangerouslySetInnerHTML={{
                    __html: t('user.emptyClosetMsg', {
                      url: `${pcs.base_url}/skinlib?filter=${category}`,
                    }),
                  }}
                ></span>
              )}
            </div>
          ) : (
            <div className="d-flex flex-wrap">
              {items.map((item, i) => (
                <ClosetItem
                  key={item.tid}
                  item={item}
                  selected={isSelected(item)}
                  onClick={handleSelect}
                  onRename={() => renameItem(item, i)}
                  onRemove={() => removeItem(item)}
                />
              ))}
            </div>
          )}
        </div>
        <Container {...({ className: 'user-card-footer', variant: 'light' } as any)}>
          <div className="float-right">
            <Pagination
              page={page}
              totalPages={totalPages}
              onChange={handlePageChange}
            />
          </div>
        </Container>
      </Card>
      <Previewer
        skin={skin?.hash}
        cape={cape?.hash}
        isAlex={skin?.type === TextureType.Alex}
      >
        <div className="d-flex justify-content-between">
          <OreButton {...({ onClick: applyToPlayer } as any)}>
            {t('user.useAs')}
          </OreButton>
          <OreButton
            {...({ color: 'secondary', onClick: resetSelected } as any)}
          >
            {t('user.resetSelected')}
          </OreButton>
        </div>
      </Previewer>
      <ModalApply
        show={showModalApply}
        canAdd
        skin={skin?.tid}
        cape={cape?.tid}
        onClose={() => setShowModalApply(false)}
      />
    </>
  )
}

export default Closet
