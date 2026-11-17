const pcsElement = document.querySelector('#pcs-globals')!
// @ts-ignore
window.pcs = JSON.parse(pcsElement.textContent!)

window.addEventListener('load', () => {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register(`${pcs.base_url}/sw.js?go-m2`)
  }
})

export {}
