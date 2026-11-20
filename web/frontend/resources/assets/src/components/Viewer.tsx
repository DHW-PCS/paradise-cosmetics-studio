/** @jsxImportSource @emotion/react */
import React, { useState, useEffect, useRef } from 'react'
import { css } from '@emotion/react'
import styled from '@emotion/styled'
import * as skinview3d from 'skinview3d'
import { t } from '@/scripts/i18n'
import * as breakpoints from '@/styles/breakpoints'
import { Card } from '@oreui-web/react/card'
import { Container } from '@oreui-web/react/container'
import { Button } from '@oreui-web/react/button'
import SkinSteve from '../../../misc/textures/steve.png'
import bg1 from '../../../misc/backgrounds/1.webp'
import bg2 from '../../../misc/backgrounds/2.webp'
import bg3 from '../../../misc/backgrounds/3.webp'
import bg4 from '../../../misc/backgrounds/4.webp'
import bg5 from '../../../misc/backgrounds/5.webp'
import bg6 from '../../../misc/backgrounds/6.webp'
import bg7 from '../../../misc/backgrounds/7.webp'

const backgrounds = [bg1, bg2, bg3, bg4, bg5, bg6, bg7]
export const PICTURES_COUNT = backgrounds.length

interface Props {
  children?: React.ReactNode
  skin?: string
  cape?: string
  isAlex: boolean
  showIndicator?: boolean
  initPositionZ?: number
}

type AnimationHandles = {
  walk: skinview3d.SubAnimationHandle | null
  run: skinview3d.SubAnimationHandle | null
  rotate: skinview3d.SubAnimationHandle | null
}

const animationHandles: AnimationHandles = {
  walk: null,
  run: null,
  rotate: null,
}

const ActionButton = styled.i`
  display: inline;
  padding: 0.5em 0.5em;
  &:hover {
    color: #555;
    cursor: pointer;
  }
`

const cssViewer = css`
  ${breakpoints.greaterThan(breakpoints.Breakpoint.lg)} {
    min-height: 500px;
  }
  width: 100%;

  canvas {
    cursor: move;
  }
`

const Viewer: React.FC<Props> = (props) => {
  const { initPositionZ = 70 } = props

  const viewRef: React.MutableRefObject<skinview3d.SkinViewer> = useRef(null!)
  const containerRef = useRef<HTMLCanvasElement>(null)
  const animationHandlesRef = useRef(animationHandles)

  const [paused, setPaused] = useState(false)
  const [running, setRunning] = useState(false)
  const [bgPicture, setBgPicture] = useState(-1)

  const indicator = (() => {
    const { skin, cape } = props
    if (skin && cape) {
      return `${t('general.skin')} & ${t('general.cape')}`
    } else if (skin) {
      return t('general.skin')
    } else if (cape) {
      return t('general.cape')
    }
    return ''
  })()

  useEffect(() => {
    const container = containerRef.current!
    const viewer = new skinview3d.FXAASkinViewer({
      canvas: container,
      width: container.clientWidth,
      height: container.clientHeight,
      skin: props.skin || SkinSteve,
      cape: props.cape || '',
      model: props.isAlex ? 'slim' : 'default',
      zoom: initPositionZ / 100,
    })

    if (document.body.classList.contains('dark-mode')) {
      viewer.background = '#6c757d'
    }

    const rotate = viewer.animations.add(skinview3d.RotatingAnimation)
    animationHandlesRef.current.rotate = rotate

    const control = skinview3d.createOrbitControls(viewer)

    viewRef.current = viewer

    return () => {
      control.dispose()
      viewer.dispose()
    }
  }, [])

  useEffect(() => {
    const canvas = containerRef.current
    if (!canvas) {
      return
    }
    const resize = () => {
      const viewer = viewRef.current
      const parent = canvas.parentElement
      const width = parent?.clientWidth ?? canvas.clientWidth
      const height = parent?.clientHeight ?? canvas.clientHeight
      if (!viewer || !width) {
        return
      }
      viewer.setSize(width, Math.max(height, 300))
    }
    const observer = new ResizeObserver(resize)
    // observe the wrapper instead of the canvas: the canvas width is pinned
    // inline by setSize, so it would never re-fire when the layout narrows
    observer.observe(canvas.parentElement ?? canvas)
    window.addEventListener('resize', resize)
    return () => {
      observer.disconnect()
      window.removeEventListener('resize', resize)
    }
  }, [])

  useEffect(() => {
    const viewer = viewRef.current
    viewer.loadSkin(props.skin || SkinSteve, props.isAlex ? 'slim' : 'default')
  }, [props.skin, props.isAlex])

  useEffect(() => {
    const viewer = viewRef.current
    if (props.cape) {
      viewer.loadCape(props.cape)
    } else {
      viewer.resetCape()
    }
  }, [props.cape])

  useEffect(() => {
    const handles = animationHandlesRef.current
    if (running) {
      handles.walk?.resetAndRemove()
      handles.walk = null

      const run = viewRef.current.animations.add(skinview3d.RunningAnimation)
      run.speed = 0.6
      handles.run = run
    } else {
      handles.run?.resetAndRemove()
      handles.run = null

      const walk = viewRef.current.animations.add(skinview3d.WalkingAnimation)
      handles.walk = walk
    }
  }, [running])

  useEffect(() => {
    viewRef.current.animations.paused = paused
  }, [paused])

  useEffect(() => {
    viewRef.current.loadBackground(backgrounds[bgPicture]!)
  }, [bgPicture])

  const togglePause = () => {
    setPaused((paused) => !paused)
  }

  const toggleRun = () => {
    setRunning((running) => !running)
  }

  const toggleRotate = () => {
    const handles = animationHandlesRef.current
    if (handles.rotate) {
      handles.rotate.paused = !handles.rotate.paused
    }
  }

  const handleReset = () => {
    const handles = animationHandlesRef.current
    handles.walk?.resetAndRemove()
    handles.run?.resetAndRemove()
    handles.rotate?.resetAndRemove()
    viewRef.current.animations.paused = true
  }

  const setWhite = () => {
    viewRef.current.background = '#fff'
  }
  const setGray = () => {
    viewRef.current.background = '#6c757d'
  }
  const setBlack = () => {
    viewRef.current.background = '#000'
  }
  const setPrevPicture = () => {
    setBgPicture((index) => {
      if (bgPicture <= 0) {
        return PICTURES_COUNT - 1
      } else {
        return index - 1
      }
    })
  }
  const setNextPicture = () => {
    setBgPicture((index) => {
      if (bgPicture >= PICTURES_COUNT - 1) {
        return 0
      } else {
        return index + 1
      }
    })
  }

  return (
    <Card {...({ className: 'user-card preview-card' } as any)}>
      <Container {...({ className: 'user-card-header', variant: 'light' } as any)}>
        <div className="d-flex justify-content-between w-100">
          <h2>
            <span>{t('general.texturePreview')}</span>
            {props.showIndicator && (
              <span className="badge bg-olive ml-1">{indicator}</span>
            )}
          </h2>
          <div>
            <ActionButton
              className={`fas fa-${running ? 'walking' : 'running'}`}
              data-toggle="tooltip"
              data-placement="bottom"
              title={`${t('general.walk')} / ${t('general.run')}`}
              onClick={toggleRun}
            ></ActionButton>
            <ActionButton
              className="fas fa-redo-alt"
              data-toggle="tooltip"
              data-placement="bottom"
              title={t('general.rotation')}
              onClick={toggleRotate}
            ></ActionButton>
            <ActionButton
              className={`fas fa-${paused ? 'play' : 'pause'}`}
              data-toggle="tooltip"
              data-placement="bottom"
              title={t('general.pause')}
              onClick={togglePause}
            ></ActionButton>
            <ActionButton
              className="fas fa-stop"
              data-toggle="tooltip"
              data-placement="bottom"
              title={t('general.reset')}
              onClick={handleReset}
            ></ActionButton>
          </div>
        </div>
      </Container>
      <div className="ore-card-body user-card-body">
        <canvas ref={containerRef} css={cssViewer}></canvas>
      </div>
      <Container {...({ className: 'user-card-footer', variant: 'light' } as any)}>
        <div className="preview-swatches">
          <Button
            {...({
              className: 'preview-swatch preview-swatch-white',
              title: t('colors.white'),
              onClick: setWhite,
            } as any)}
          />
          <Button
            {...({
              className: 'preview-swatch preview-swatch-black',
              title: t('colors.black'),
              onClick: setBlack,
            } as any)}
          />
          <Button
            {...({
              className: 'preview-swatch preview-swatch-gray',
              title: t('colors.gray'),
              onClick: setGray,
            } as any)}
          />
          <Button
            {...({
              className: 'preview-swatch preview-swatch-nav',
              title: t('colors.prev'),
              onClick: setPrevPicture,
            } as any)}
          >
            <svg viewBox="0 0 8 8" aria-hidden="true">
              <path
                fill="currentColor"
                fillRule="evenodd"
                d="M5 2h1V1H5zM2 5h1V4H2zm3-3H4v1h1-1v.003H3v1h1-1V6h1v-.997 1h.034V7H5v1h1V2z"
                transform="translate(0 -.5)"
              />
            </svg>
          </Button>
          <Button
            {...({
              className: 'preview-swatch preview-swatch-nav',
              title: t('colors.next'),
              onClick: setNextPicture,
            } as any)}
          >
            <svg viewBox="0 0 8 8" aria-hidden="true">
              <path
                fill="currentColor"
                fillRule="evenodd"
                d="M3 7H2v1h1zm3-3H5v1h1zM3 7h1V6H3h1v-.003h1v-1H4h1V3H4v.997-1h-.034V2H3V1H2v6z"
                transform="translate(0 -.5)"
              />
            </svg>
          </Button>
        </div>
        {props.children}
      </Container>
    </Card>
  )
}

export default Viewer
