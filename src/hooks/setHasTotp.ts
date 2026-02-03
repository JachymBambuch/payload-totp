import type { FieldHook, User } from 'payload'

import type { PayloadTOTPConfig } from '../types.js'

import { getTotpSecret } from '../utilities/getTotpSecret.js'

// Symbol to track recursion in request context
const TOTP_FETCHING_SECRET = Symbol.for('payload-totp-fetching-secret')

export const setHasTotp: (pluginOptions: PayloadTOTPConfig) => FieldHook =
	(pluginOptions) =>
	async ({ collection, data, req }) => {
		const { payload } = req

		// Prevent infinite recursion - if we're already fetching TOTP secret, skip
		if ((req.context as any)?.[TOTP_FETCHING_SECRET]) {
			return false
		}

		const totpSecret = await getTotpSecret({
			collection: collection?.slug || pluginOptions.collection,
			payload,
			req,
			user: data as User,
		})

		return Boolean(totpSecret)
	}
