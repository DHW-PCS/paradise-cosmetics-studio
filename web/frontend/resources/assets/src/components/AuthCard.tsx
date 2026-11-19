import React from 'react'
import { Card } from '@oreui-web/react/card'

type Props = {
  title: string
  onSubmit: React.FormEventHandler<HTMLFormElement>
  children: React.ReactNode
  actions: React.ReactNode
}

const AuthCard: React.FC<Props> = ({ title, onSubmit, children, actions }) => {
  const description =
    document.querySelector<HTMLElement>('.auth-root')?.dataset.notice

  return (
    <Card {...({ className: 'auth-card' } as any)}>
      <header className="auth-card-titlebar">
        <button
          aria-label="Back"
          className="auth-card-back ore-modal-header-button"
          type="button"
          onClick={() => {
            window.location.href = pcs.route === 'auth/login'
              ? `${pcs.base_url}/`
              : `${pcs.base_url}/auth/login`
          }}
        >
          <svg aria-hidden="true" viewBox="0 0 8 8">
            <path
              d="M5 2h1V1H5zM2 5h1V4H2zm3-3H4v1h1-1v.003H3v1h1-1V6h1v-.997 1h.034V7H5v1h1V2z"
              fill="currentColor"
              fillRule="evenodd"
              transform="translate(0 -.5)"
            />
          </svg>
        </button>
        <h1 className="auth-card-title">{title}</h1>
      </header>
      <form className="auth-card-form" onSubmit={onSubmit}>
        <div className="auth-card-body">
          <div className="auth-card-content">
            {description && (
              <p className="auth-card-description">{description}</p>
            )}
            {children}
          </div>
        </div>
        <footer className="auth-card-actions">{actions}</footer>
      </form>
    </Card>
  )
}

export default AuthCard
