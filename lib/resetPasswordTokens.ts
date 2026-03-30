/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { timingSafeEqual } from 'node:crypto'
import { users } from '../data/datacache'
import { ResetPasswordTokenModel } from '../models/resetPasswordToken'
import { type UserModel } from '../models/user'
import { createResetPasswordToken, getResetPasswordTokenExpiry } from './resetPasswordTokenUtils'

async function storeResetPasswordTokenBackup (user: UserModel, date = new Date()): Promise<void> {
  const token = createResetPasswordToken(user.email, date)
  const expiresAt = getResetPasswordTokenExpiry(date)

  await ResetPasswordTokenModel.findOrCreate({
    where: { token },
    defaults: {
      UserId: user.id,
      token,
      expiresAt
    }
  })
}

export async function isValidResetPasswordToken (user: UserModel, token: string): Promise<boolean> {
  const expectedToken = createResetPasswordToken(user.email)
  if (token.length !== expectedToken.length) {
    return false
  }
  return timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))
}

export async function seedResetPasswordTokens (): Promise<void> {
  const seedPlan = [
    { user: users.admin, dayOffsets: [-3, -2, -1] },
    { user: users.jim, dayOffsets: [-3, -2, -1, 0] },
    { user: users.bender, dayOffsets: [-3, -2, -1, 0] },
    { user: users.bjoern, dayOffsets: [-3, -2, -1, 0] }
  ]

  for (const { user, dayOffsets } of seedPlan) {
    if (!user) {
      continue
    }
    for (const dayOffset of dayOffsets) {
      const date = new Date()
      date.setDate(date.getDate() + dayOffset)
      await storeResetPasswordTokenBackup(user, date)
    }
  }
}
