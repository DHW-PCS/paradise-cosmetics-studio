import { useState, useEffect } from 'react'

export default function usePCSExtra<T>(key: string, defaultValue?: T): T {
  const [value, setValue] = useState<T>(defaultValue!)

  useEffect(() => {
    setValue(pcs.extra[key] as T)
  }, [key])

  return value
}
