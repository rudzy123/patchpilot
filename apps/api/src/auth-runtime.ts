import type {
  createListActiveOrganizationsUseCase,
  createLoginUseCase,
  createLogoutUseCase,
  createReadSessionUseCase,
  createResolveSessionUseCase,
  createSelectOrganizationUseCase,
} from '@patchpilot/auth';
import type { AuditAppendRepository } from '@patchpilot/domain';

export type AuthRuntime = {
  login: ReturnType<typeof createLoginUseCase>;
  logout: ReturnType<typeof createLogoutUseCase>;
  resolveSession: ReturnType<typeof createResolveSessionUseCase>;
  readSession: ReturnType<typeof createReadSessionUseCase>;
  selectOrganization: ReturnType<typeof createSelectOrganizationUseCase>;
  listOrganizations: ReturnType<typeof createListActiveOrganizationsUseCase>;
  audit: Pick<AuditAppendRepository, 'append'>;
};
