import './init' // must be first
import 'admin-lte'
import 'oreui-web/navbar'
import 'oreui-web/dropdown'
import 'oreui-web/scrollbar'
import 'oreui-web/card'
import 'oreui-web/container'
import 'oreui-web/accordion'
import 'oreui-web/icon-button'
import 'oreui-web/button'
import 'oreui-web/textfield'
import 'oreui-web/textarea'
import 'oreui-web/table'
import './extra'
import './i18n'
import './net'
import './event'
import './notification'
import './emailVerification'
import './logout'
import './yggdrasilDnd'
import './yggdrasilConfig'

window.addEventListener('load', () => {
  $('[data-toggle="tooltip"]').tooltip()
})
