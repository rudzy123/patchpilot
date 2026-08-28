import type { EnvironmentRepository, MembershipRepository, TeamRepository } from '../ports.js';
import { err, ok, type Result } from '../result.js';
import {
  ENVIRONMENT_NOT_ASSIGNABLE,
  MEMBERSHIP_NOT_ASSIGNABLE,
  TEAM_NOT_ASSIGNABLE,
} from './errors.js';
import type {
  AssetOwnerAssignment,
  NormalizedCreateAssetCommand,
  NormalizedUpdateAssetCommand,
} from './types.js';

export type AssignmentLookups = {
  environments: Pick<EnvironmentRepository, 'findById'>;
  teams: Pick<TeamRepository, 'findById'>;
  memberships: Pick<MembershipRepository, 'findById'>;
};

export async function validateCreateAssignments(
  lookups: AssignmentLookups,
  organizationId: string,
  command: NormalizedCreateAssetCommand,
): Promise<Result<void>> {
  return validateAssignments(lookups, organizationId, {
    ...(command.environmentId === undefined ? {} : { environmentId: command.environmentId }),
    ...(command.owningTeamId === undefined ? {} : { owningTeamId: command.owningTeamId }),
    owners: command.owners,
  });
}

export async function validateUpdateAssignments(
  lookups: AssignmentLookups,
  organizationId: string,
  command: NormalizedUpdateAssetCommand,
): Promise<Result<void>> {
  return validateAssignments(lookups, organizationId, {
    ...(command.environmentId === undefined ? {} : { environmentId: command.environmentId }),
    ...(command.owningTeamId === undefined ? {} : { owningTeamId: command.owningTeamId }),
    ...(command.owners === undefined ? {} : { owners: command.owners }),
  });
}

async function validateAssignments(
  lookups: AssignmentLookups,
  organizationId: string,
  input: {
    environmentId?: string | null;
    owningTeamId?: string | null;
    owners?: readonly AssetOwnerAssignment[];
  },
): Promise<Result<void>> {
  if (input.environmentId !== undefined && input.environmentId !== null) {
    const environment = await lookups.environments.findById(organizationId, input.environmentId);
    if (environment === undefined || environment.status !== 'active') {
      return err(ENVIRONMENT_NOT_ASSIGNABLE);
    }
  }

  const teamIds = uniqueIds([
    ...(input.owningTeamId === undefined || input.owningTeamId === null
      ? []
      : [input.owningTeamId]),
    ...(input.owners ?? []).filter((owner) => owner.kind === 'team').map((owner) => owner.teamId),
  ]);
  for (const teamId of teamIds) {
    const team = await lookups.teams.findById(organizationId, teamId);
    if (team === undefined || team.status !== 'active') {
      return err(TEAM_NOT_ASSIGNABLE);
    }
  }

  const membershipIds = uniqueIds(
    (input.owners ?? [])
      .filter((owner) => owner.kind === 'membership')
      .map((owner) => owner.membershipId),
  );
  for (const membershipId of membershipIds) {
    const membership = await lookups.memberships.findById(organizationId, membershipId);
    if (membership === undefined || membership.status !== 'active') {
      return err(MEMBERSHIP_NOT_ASSIGNABLE);
    }
  }

  return ok(undefined);
}

function uniqueIds(values: readonly string[]): string[] {
  return [...new Set(values)];
}
