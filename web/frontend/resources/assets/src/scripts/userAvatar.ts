export default function updateUserAvatar(tid: number) {
  const avatar = `${blessing.base_url}/avatar/${tid}?size=45`
  document
    .querySelectorAll<HTMLImageElement>('[alt="User Image"]')
    .forEach((image) => {
      image.closest('picture')!.querySelector<HTMLSourceElement>('source')!.srcset =
        avatar
      image.src = `${avatar}&png=1`
    })
}
