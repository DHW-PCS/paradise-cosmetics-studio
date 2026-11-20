import React, { useState, useEffect, useCallback } from 'react'
import styled from '@emotion/styled'
import useEmitMounted from '@/scripts/hooks/useEmitMounted'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { toast } from '@/scripts/notify'
import useTween from '@/scripts/hooks/useTween'
import urls from '@/scripts/urls'
import * as breakpoints from '@/styles/breakpoints'
import { Card } from '@oreui-web/react/card'
import { Container } from '@oreui-web/react/container'
import InfoBox from './InfoBox'
import SignButton from './SignButton'
import * as scoreUtils from './scoreUtils'

type ScoreInfo = {
  signAfterZero: boolean
  signGapTime: number
  rate: { players: number; storage: number }
  usage: { players: number; storage: number }
  user: { score: number; lastSignAt: string }
}

type SignReturn = {
  score: number
}

const ScoreTitle = styled.p`
  font-weight: bold;
  margin-top: 5px;
  ${breakpoints.lessThan(breakpoints.Breakpoint.md)} {
    margin-top: 12px;
  }
`
const Score = styled.p`
  font-family: 'Minecraft';
  font-size: 50px;
  margin-top: 20px;
  cursor: help;
`
const ScoreNotice = styled.p`
  font-size: smaller;
  margin-top: 20px;
`

const Dashboard: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [players, setPlayers] = useState(0)
  const [storage, setStorage] = useState(0)
  const [score, setScore] = useState(0)
  const [tweenedScore, setTweenedScore] = useTween(0)
  const [playersRate, setPlayersRate] = useState(1)
  const [storageRate, setStorageRate] = useState(1)
  const [lastSign, setLastSign] = useState(new Date())
  const [canSignAfterZero, setCanSignAfterZero] = useState(false)
  const [signGap, setSignGap] = useState(24)

  useEmitMounted()

  useEffect(() => {
    const fetchInfo = async () => {
      setLoading(true)
      const data = await fetch.get<ScoreInfo>(urls.user.score())
      setPlayers(data.usage.players)
      setStorage(data.usage.storage)
      setTweenedScore(data.user.score)
      setScore(data.user.score)
      setPlayersRate(data.rate.players)
      setStorageRate(data.rate.storage)
      setLastSign(new Date(data.user.lastSignAt))
      setCanSignAfterZero(data.signAfterZero)
      setSignGap(data.signGapTime)
      setLoading(false)
    }
    fetchInfo()
  }, [])

  const handleSign = useCallback(async () => {
    setLoading(true)
    const { code, message, data } = await fetch.post<
      fetch.ResponseBody<SignReturn>
    >(urls.user.sign())

    if (code === 0) {
      toast.success(message)
      setLastSign(new Date())
      setTweenedScore(data.score)
      setScore(data.score)
    } else if (code === 1) {
      const remainingTime = scoreUtils.remainingTime(
        lastSign,
        signGap,
        canSignAfterZero,
      )
      toast.warning(scoreUtils.remainingTimeText(remainingTime))
    } else {
      toast.error(message)
    }
    setLoading(false)
  }, [])

  return (
    <Card {...({ className: 'user-card usage-card' } as any)}>
      <Container
        {...({ className: 'user-card-header', variant: 'light' } as any)}
      >
        <h2>{t('user.used.title')}</h2>
      </Container>
      <div className="ore-card-body user-card-body">
        <div className="dashboard-usage-grid">
          <div className="dashboard-usage-stats">
            <InfoBox
              color="teal"
              icon="gamepad"
              name={t('user.used.players')}
              used={players}
              unused={score / playersRate}
              unit=""
            />
            {storage > 1024 ? (
              <InfoBox
                color="maroon"
                icon="hdd"
                name={t('user.used.storage')}
                used={~~(storage / 1024)}
                unused={~~(score / storageRate / 1024)}
                unit="MB"
              />
            ) : (
              <InfoBox
                color="maroon"
                icon="hdd"
                name={t('user.used.storage')}
                used={storage}
                unused={score / storageRate}
                unit="KB"
              />
            )}
          </div>
          <div className="dashboard-usage-score">
            <ScoreTitle>{t('user.cur-score')}</ScoreTitle>
            <Score data-toggle="modal" data-target="#modal-score-instruction">
              {~~tweenedScore}
            </Score>
            <ScoreNotice>{t('user.score-notice')}</ScoreNotice>
          </div>
        </div>
      </div>
      <Container
        {...({ className: 'user-card-footer', variant: 'light' } as any)}
      >
        <SignButton
          isLoading={loading}
          lastSign={lastSign}
          canSignAfterZero={canSignAfterZero}
          signGap={signGap}
          onClick={handleSign}
        />
      </Container>
    </Card>
  )
}

export default Dashboard
