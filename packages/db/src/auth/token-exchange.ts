import * as schema from '@db/schema';

import { eq } from 'drizzle-orm';
import { jwtVerify } from 'jose';

import { getAllActiveTokenAuth } from '@db/queries/organization/token-auth';
import { ensureOrgMembership } from './hooks/sso-provisioning';
import { db } from '@db/drizzle';
import { ZTokenExchangePayload } from '@cio/utils/validation/organization';
import type { User } from 'better-auth';

const MAX_TOKEN_AGE_SEC = 5 * 60; // 5 minutes

export class TokenExchangeError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number
  ) {
    super(message);
    this.name = 'TokenExchangeError';
  }
}

/**
 * Exchange a JWT token for a user and org. Verifies signature with org's signing secret,
 * finds or creates user, ensures org membership. Caller is responsible for creating session and setting cookie.
 */
function profileUsername(email: string): string {
  const emailPrefix = email.match(/^([^@]+)@/)?.[1] ?? 'user';
  return `${emailPrefix}${Date.now()}`;
}

async function ensureProfile(user: User, avatar?: string): Promise<void> {
  const [existingProfile] = await db.select().from(schema.profile).where(eq(schema.profile.id, user.id)).limit(1);
  const now = new Date().toISOString();

  if (existingProfile) {
    const profileUpdates: Partial<typeof schema.profile.$inferInsert> = {
      email: user.email,
      fullname: user.name,
      isEmailVerified: true,
      verifiedAt: existingProfile.verifiedAt ?? now,
      updatedAt: now
    };
    if (avatar) profileUpdates.avatarUrl = avatar;

    await db.update(schema.profile).set(profileUpdates).where(eq(schema.profile.id, user.id));
    return;
  }

  await db.insert(schema.profile).values({
    id: user.id,
    username: profileUsername(user.email ?? user.id),
    fullname: user.name,
    email: user.email ?? undefined,
    avatarUrl: avatar,
    isEmailVerified: true,
    verifiedAt: now,
    role: 'student'
  });
}

async function findOrCreateUser(email: string, name: string, avatar?: string): Promise<User> {
  const [existingUser] = await db.select().from(schema.user).where(eq(schema.user.email, email)).limit(1);

  if (existingUser) {
    const userUpdates: Partial<typeof schema.user.$inferInsert> = {
      name,
      emailVerified: true,
      updatedAt: new Date()
    };
    if (avatar) userUpdates.image = avatar;

    const [updatedUser] = await db
      .update(schema.user)
      .set(userUpdates)
      .where(eq(schema.user.id, existingUser.id))
      .returning();

    return (updatedUser ?? existingUser) as User;
  }

  const [createdUser] = await db
    .insert(schema.user)
    .values({
      name,
      email,
      emailVerified: true,
      image: avatar
    })
    .returning();

  if (!createdUser) {
    throw new TokenExchangeError('Failed to create user', 'TOKEN_EXCHANGE_USER_CREATE_FAILED', 500);
  }

  return createdUser as User;
}

export async function exchangeToken(token: string): Promise<{ user: User; orgId: string }> {
  const configs = await getAllActiveTokenAuth();
  const envSigningSecret = process.env.FARTHER_LMS_TOKEN_EXCHANGE_SECRET ?? process.env.CLASSROOMIO_TOKEN_EXCHANGE_SECRET;
  const envOrganizationId = process.env.FARTHER_LMS_ORG_ID ?? process.env.CLASSROOMIO_ORG_ID;

  if (envSigningSecret && envOrganizationId) {
    configs.push({
      organizationId: envOrganizationId,
      signingSecret: envSigningSecret
    });
  }

  if (configs.length === 0) {
    throw new TokenExchangeError('No active token auth configured', 'TOKEN_EXCHANGE_NOT_ENABLED', 403);
  }

  let payload: unknown;
  let orgId: string | null = null;

  for (const config of configs) {
    const secret = new TextEncoder().encode(config.signingSecret);
    try {
      const { payload: verified } = await jwtVerify(token, secret, {
        algorithms: ['HS256'],
        maxTokenAge: MAX_TOKEN_AGE_SEC
      });
      payload = verified;
      orgId = config.organizationId;
      break;
    } catch {
      continue;
    }
  }

  if (!orgId) {
    throw new TokenExchangeError('Invalid token', 'TOKEN_EXCHANGE_INVALID_TOKEN', 400);
  }

  const parsed = ZTokenExchangePayload.safeParse(payload);
  if (!parsed.success) {
    throw new TokenExchangeError('Invalid token payload', 'TOKEN_EXCHANGE_INVALID_TOKEN', 400);
  }

  const { email, name, avatar } = parsed.data;
  const emailLower = email.toLowerCase();

  const user = await findOrCreateUser(emailLower, name ?? emailLower.split('@')[0], avatar);
  await ensureProfile(user, avatar);

  await ensureOrgMembership(user.id, user.email ?? emailLower, orgId);

  if (avatar) {
    await db
      .update(schema.profile)
      .set({ avatarUrl: avatar, updatedAt: new Date().toISOString() })
      .where(eq(schema.profile.id, user.id));
  }

  return {
    user: {
      ...user,
      image: user.image ?? null
    },
    orgId
  };
}
