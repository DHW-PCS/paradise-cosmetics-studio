import { showModal, toast } from '@/scripts/notify'
import { t } from '@/scripts/i18n'
import { post, ResponseBody } from '@/scripts/net'
import updateUserAvatar from '@/scripts/userAvatar'

export default async function resetAvatar() {
  try {
    await showModal({ text: t('user.resetAvatarConfirm') })
  } catch {
    return
  }

  const { code, message }: ResponseBody = await post('/user/profile/avatar', {
    tid: 0,
  })
  if (code === 0) {
    toast.success(message)
    updateUserAvatar(0)
  } else {
    toast.error(message)
  }
}
