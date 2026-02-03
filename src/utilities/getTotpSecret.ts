import type { Payload, PayloadRequest, User } from 'payload'

// Symbol to track recursion in request context
const TOTP_FETCHING_SECRET = Symbol.for('payload-totp-fetching-secret')

type Args = {
	collection: string
	payload: Payload
	req?: PayloadRequest
	user: User
}

export async function getTotpSecret({
	collection,
	payload,
	req,
	user,
}: Args): Promise<string | undefined> {
	if (!user) {
		return undefined
	}

	let totpSecret: string | undefined

	try {
		// Create context with recursion guard
		const context = req?.context
			? { ...req.context, [TOTP_FETCHING_SECRET]: true }
			: { [TOTP_FETCHING_SECRET]: true }

		const result = (await payload.findByID({
			id: user.id,
			collection,
			context,
			overrideAccess: true,
			select: {
				totpSecret: true,
			},
			showHiddenFields: true,
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any)) as { totpSecret?: null | string } // TODO: Report this to Payload
		totpSecret = result.totpSecret === null ? undefined : result.totpSecret
		// eslint-disable-next-line @typescript-eslint/no-unused-vars, no-empty
	} catch (err) {}

	return totpSecret
}
