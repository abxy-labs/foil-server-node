import { Foil, FoilApiError, safeVerifyFoilToken } from '@abxy/foil-server';
import type { SessionDetail, VerifiedFoilToken } from '@abxy/foil-server';

export const client: Foil = new Foil();

export function errorStatus(error: unknown): number | undefined {
  return error instanceof FoilApiError ? error.status : undefined;
}

export type PublicTypes = [SessionDetail, VerifiedFoilToken, ReturnType<typeof safeVerifyFoilToken>];
