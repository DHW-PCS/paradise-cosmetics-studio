import { toast } from './notify'
import { post } from './net'
import { t } from './i18n'

// Legacy keypair generate action: request one candidate private key and
// fill it into the form; the key is saved only by the explicit submit.
document
  .querySelector('[name=generate-key]')
  ?.addEventListener('click', async () => {
    type Ok = { code: 0; key: string }
    type Err = { code: 1; message: string }

    const response: Ok | Err = await post(
      '/admin/plugins/config/yggdrasil-api/generate',
    )

    if (response.code === 0) {
      toast.success(t('yggdrasil-api.key-generated'))

      document.querySelector<any>(
        'ore-textarea[name=ygg_private_key]',
      )!.value = response.key
      const form = document.querySelector('input[value=keypair]')!
        .parentElement as HTMLFormElement
      form.submit()
    } else {
      toast.error(response.message)
    }
  })
