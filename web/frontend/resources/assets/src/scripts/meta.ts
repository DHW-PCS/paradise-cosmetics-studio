const blessingElement = document.querySelector('#blessing-globals')!
// @ts-ignore
window.blessing = JSON.parse(blessingElement.textContent!)

window.addEventListener('load', () => {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register(`${blessing.base_url}/sw.js?go-m2`)
  }
})

export {}
