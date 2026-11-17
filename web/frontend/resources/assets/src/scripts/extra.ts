export function getExtraData(): Record<string, any> {
  const jsonElement = document.querySelector('#pcs-extra')
  /* istanbul ignore next */
  if (jsonElement) {
    return JSON.parse(jsonElement.textContent ?? '{}')
  } else {
    return {}
  }
}

pcs.extra = getExtraData()
