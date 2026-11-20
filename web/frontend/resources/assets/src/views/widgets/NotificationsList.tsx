import React, { useState, useEffect } from 'react'
import * as fetch from '@/scripts/net'
import { showModal } from '@/scripts/notify'
import { Dropdown } from '@oreui-web/react/dropdown'

export type Notification = {
  id: string
  title: string
}

const NotificationsList: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [noUnreadText, setNoUnreadText] = useState('')

  useEffect(() => {
    const dataset = document.querySelector<HTMLElement>(
      '[data-notifications]',
    )?.dataset
    if (dataset) {
      const notifications: Notification[] = JSON.parse(dataset.notifications!)
      setNotifications(notifications)
      setNoUnreadText(dataset.t!)
    }
  }, [])

  const read = async (id: string) => {
    const { title, content, time } = await fetch.post<{
      title: string
      content: string
      time: string
    }>(`/user/notifications/${id}`)

    showModal({
      mode: 'alert',
      title,
      children: (
        <>
          <div dangerouslySetInnerHTML={{ __html: content }}></div>
          <br />
          <small>{time}</small>
        </>
      ),
    })
    setNotifications((notifications) =>
      notifications.filter((notification) => notification.id !== id),
    )
  }

  const hasUnread = notifications.length > 0

  return (
    <Dropdown {...({ className: 'app-navbar-dropdown app-navbar-notice-menu' } as any)}>
      <button className="ore-dropdown-trigger app-navbar-action" type="button" aria-label={noUnreadText}>
        <i className="far fa-bell" aria-hidden="true"></i>
        {hasUnread && <span className="app-navbar-notice-count">{notifications.length}</span>}
      </button>
      <div className="ore-dropdown-menu">
        {hasUnread ? (
          notifications.map((notification) => (
            <button
              className="ore-dropdown-item"
              data-value={notification.id}
              type="button"
              key={notification.id}
              onClick={() => read(notification.id)}
            >
              {notification.title}
            </button>
          ))
        ) : (
          <p className="app-navbar-no-notifications">{noUnreadText}</p>
        )}
      </div>
    </Dropdown>
  )
}

export default NotificationsList
