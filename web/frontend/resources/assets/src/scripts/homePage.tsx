import React from 'react'
import { createRoot } from 'react-dom/client'
import { Button } from '@oreui-web/react/button'
import { Navbar } from '@oreui-web/react/navbar'
import { getExtraData } from './extra'

export function scrollHander() {
  const header = document.querySelector('#home-navbar > ore-navbar')
  /* istanbul ignore else */
  if (header) {
    window.addEventListener('scroll', () => {
      if (window.scrollY >= (window.innerHeight * 2) / 3) {
        header.classList.remove('transparent')
      } else {
        header.classList.add('transparent')
      }
    })
  }
}

const navbar = document.querySelector<HTMLElement>('#home-navbar')
if (navbar) {
  const content = navbar.innerHTML
  const className = navbar.dataset.navbarClass || ''
  createRoot(navbar).render(
    <Navbar
      {...({
        className,
        dangerouslySetInnerHTML: { __html: content },
      } as React.HTMLAttributes<HTMLElement>)}
    />,
  )
}

document.querySelectorAll<HTMLElement>('[data-oreui-button]').forEach((mount) => {
  const { href, label } = mount.dataset
  if (!href || !label) {
    return
  }
  createRoot(mount).render(
    <Button {...({ href, color: 'primary', variant: 'hero' } as any)}>
      {label}
    </Button>,
  )
})

/* istanbul ignore next */
if (process.env.NODE_ENV !== 'test') {
  const { transparent_navbar } = getExtraData() as {
    transparent_navbar: boolean
  }
  if (transparent_navbar) {
    window.addEventListener('load', scrollHander)
  }
}
