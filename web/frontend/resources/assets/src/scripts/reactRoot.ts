import type { ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'

const roots = new WeakMap<Element, Root>()

export function render(element: ReactNode, container: Element): void {
  let root = roots.get(container)
  if (!root) {
    root = createRoot(container)
    roots.set(container, root)
  }
  root.render(element)
}

export function unmountComponentAtNode(container: Element): boolean {
  const root = roots.get(container)
  if (!root) {
    return false
  }
  root.unmount()
  roots.delete(container)
  return true
}
