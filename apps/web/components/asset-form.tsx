'use client';

import { useEffect, useId, useRef, useState, type FormEvent, type ReactElement } from 'react';

import type {
  AssetDetail,
  EnvironmentOption,
  MembershipOption,
  TeamOption,
} from '@patchpilot/contracts';

import {
  ASSET_IDENTIFIER_MAX_COUNT,
  ASSET_OWNER_MAX_COUNT,
  ASSET_TAG_MAX_COUNT,
  ASSET_TYPE_OPTIONS,
  BUSINESS_CRITICALITY_OPTIONS,
  DATA_CLASSIFICATION_OPTIONS,
  INTERNET_EXPOSURE_OPTIONS,
  OWNER_ROLE_OPTIONS,
  emptyAssetFormValues,
  toCreateBody,
  toUpdateBody,
  validateAssetForm,
  valuesFromAsset,
  type AssetFormOwner,
  type AssetFormValues,
  type FieldError,
} from '../lib/asset-form';
import {
  ASSET_VERSION_CONFLICT,
  GENERIC_ACCESS_DENIED,
  GENERIC_SESSION_EXPIRED,
  GENERIC_UNAVAILABLE,
  ORGANIZATION_CONTEXT_REQUIRED,
  isAuthRequestError,
} from '../lib/auth-api';
import { useAuth } from './auth-provider';

export function AssetForm({
  mode,
  assetId,
  initialValues,
  expectedVersion,
  readOnly = false,
  onCreated,
  onUpdated,
  onVersionConflict,
}: {
  mode: 'create' | 'edit';
  assetId?: string;
  initialValues?: AssetFormValues;
  expectedVersion?: number;
  readOnly?: boolean;
  onCreated?: (asset: AssetDetail) => void;
  onUpdated?: (asset: AssetDetail) => void;
  onVersionConflict?: () => Promise<AssetDetail | void> | AssetDetail | void;
}): ReactElement {
  const { api, getCsrfToken } = useAuth();
  const formId = useId();
  const errorRef = useRef<HTMLDivElement>(null);
  const inFlightRef = useRef(false);
  const [values, setValues] = useState<AssetFormValues>(initialValues ?? emptyAssetFormValues);
  const [fieldErrors, setFieldErrors] = useState<FieldError[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [conflictMessage, setConflictMessage] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [tagDraft, setTagDraft] = useState('');
  const [identifierNamespace, setIdentifierNamespace] = useState('');
  const [identifierValue, setIdentifierValue] = useState('');
  const [ownerKind, setOwnerKind] = useState<'membership' | 'team'>('membership');
  const [ownerTargetId, setOwnerTargetId] = useState('');
  const [ownerRole, setOwnerRole] = useState<'technical' | 'business' | 'security'>('technical');
  const [environments, setEnvironments] = useState<EnvironmentOption[]>([]);
  const [teams, setTeams] = useState<TeamOption[]>([]);
  const [memberships, setMemberships] = useState<MembershipOption[]>([]);
  const [optionsError, setOptionsError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const [environmentPage, teamPage, membershipPage] = await Promise.all([
          api.listAssetEnvironments(),
          api.listAssetTeams(),
          api.listAssetMemberships(),
        ]);
        if (cancelled) {
          return;
        }
        setEnvironments(environmentPage.items);
        setTeams(teamPage.items);
        setMemberships(membershipPage.items);
        setOptionsError(null);
      } catch (error) {
        if (cancelled) {
          return;
        }
        setOptionsError(mapAssetError(error));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api]);

  useEffect(() => {
    if (fieldErrors.length > 0 || formError !== null || conflictMessage !== null) {
      errorRef.current?.focus();
    }
  }, [conflictMessage, fieldErrors, formError]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (readOnly || inFlightRef.current) {
      return;
    }

    const nextErrors = validateAssetForm(values);
    if (nextErrors.length > 0) {
      setFieldErrors(nextErrors);
      setFormError(null);
      return;
    }

    const csrfToken = getCsrfToken();
    if (csrfToken === null) {
      setFormError(GENERIC_SESSION_EXPIRED);
      return;
    }

    inFlightRef.current = true;
    setSubmitting(true);
    setFieldErrors([]);
    setFormError(null);
    setConflictMessage(null);
    try {
      if (mode === 'create') {
        const created = await api.createAsset(toCreateBody(values), csrfToken);
        onCreated?.(created);
        return;
      }
      if (expectedVersion === undefined || assetId === undefined) {
        setFormError('Asset version is missing.');
        return;
      }
      const updated = await api.updateAsset(
        assetId,
        toUpdateBody(values, expectedVersion),
        csrfToken,
      );
      onUpdated?.(updated);
    } catch (error) {
      if (isAuthRequestError(error) && error.message === ASSET_VERSION_CONFLICT) {
        setConflictMessage(
          'This asset was updated by someone else. The current values were refreshed. Review and save again.',
        );
        const refreshed = await onVersionConflict?.();
        if (refreshed) {
          setValues(valuesFromAsset(refreshed));
        }
        return;
      }
      setFormError(mapAssetError(error));
    } finally {
      inFlightRef.current = false;
      setSubmitting(false);
    }
  }

  function fieldError(id: string): string | undefined {
    return fieldErrors.find((error) => error.id === id)?.message;
  }

  const describedBy =
    [
      fieldErrors.length > 0 || formError !== null || conflictMessage !== null
        ? `${formId}-errors`
        : undefined,
    ]
      .filter((value): value is string => value !== undefined)
      .join(' ') || undefined;

  return (
    <form onSubmit={(event) => void handleSubmit(event)} noValidate className="asset-form">
      {fieldErrors.length > 0 || formError !== null || conflictMessage !== null ? (
        <div
          id={`${formId}-errors`}
          ref={errorRef}
          role="alert"
          tabIndex={-1}
          className="auth-alert"
        >
          <p>{conflictMessage ?? formError ?? 'Correct the following errors'}</p>
          {fieldErrors.length > 0 ? (
            <ul>
              {fieldErrors.map((error) => (
                <li key={error.id}>
                  <a href={`#${error.id}`}>{error.message}</a>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      {optionsError !== null ? (
        <p role="status" className="auth-alert">
          {optionsError}
        </p>
      ) : null}

      <div className="auth-field">
        <label htmlFor="asset-name">Name</label>
        <input
          id="asset-name"
          name="name"
          value={values.name}
          onChange={(event) => setValues({ ...values, name: event.target.value })}
          disabled={readOnly}
          aria-invalid={fieldError('asset-name') !== undefined}
          aria-describedby={describedBy}
        />
      </div>

      <div className="auth-field">
        <label htmlFor="asset-type">Asset type</label>
        <select
          id="asset-type"
          name="assetType"
          value={values.assetType}
          onChange={(event) => setValues({ ...values, assetType: event.target.value })}
          disabled={readOnly}
          aria-invalid={fieldError('asset-type') !== undefined}
        >
          <option value="">Select an asset type</option>
          {ASSET_TYPE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>

      <div className="auth-field">
        <label htmlFor="asset-environment">Environment</label>
        <select
          id="asset-environment"
          name="environmentId"
          value={values.environmentId}
          onChange={(event) => setValues({ ...values, environmentId: event.target.value })}
          disabled={readOnly}
        >
          <option value="">None</option>
          {environments.map((environment) => (
            <option key={environment.id} value={environment.id}>
              {environment.name}
            </option>
          ))}
        </select>
      </div>

      <div className="auth-field">
        <label htmlFor="asset-team">Owning team</label>
        <select
          id="asset-team"
          name="owningTeamId"
          value={values.owningTeamId}
          onChange={(event) => setValues({ ...values, owningTeamId: event.target.value })}
          disabled={readOnly}
        >
          <option value="">None</option>
          {teams.map((team) => (
            <option key={team.id} value={team.id}>
              {team.name}
            </option>
          ))}
        </select>
      </div>

      <div className="auth-field">
        <label htmlFor="asset-description">Description</label>
        <textarea
          id="asset-description"
          name="description"
          value={values.description}
          onChange={(event) => setValues({ ...values, description: event.target.value })}
          disabled={readOnly}
          rows={4}
        />
      </div>

      <div className="auth-field">
        <label htmlFor="asset-criticality">Business criticality</label>
        <select
          id="asset-criticality"
          name="businessCriticality"
          value={values.businessCriticality}
          onChange={(event) => setValues({ ...values, businessCriticality: event.target.value })}
          disabled={readOnly}
        >
          {BUSINESS_CRITICALITY_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>

      <div className="auth-field">
        <label htmlFor="asset-exposure">Internet exposure</label>
        <select
          id="asset-exposure"
          name="internetExposure"
          value={values.internetExposure}
          onChange={(event) => setValues({ ...values, internetExposure: event.target.value })}
          disabled={readOnly}
        >
          {INTERNET_EXPOSURE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>

      <div className="auth-field">
        <label htmlFor="asset-classification">Data classification</label>
        <select
          id="asset-classification"
          name="dataClassification"
          value={values.dataClassification}
          onChange={(event) => setValues({ ...values, dataClassification: event.target.value })}
          disabled={readOnly}
        >
          {DATA_CLASSIFICATION_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>

      <div className="auth-field">
        <label htmlFor="asset-repository">Repository URL</label>
        <input
          id="asset-repository"
          name="repositoryUrl"
          value={values.repositoryUrl}
          onChange={(event) => setValues({ ...values, repositoryUrl: event.target.value })}
          disabled={readOnly}
          autoComplete="off"
        />
        <p className="asset-hint">Stored as text. PatchPilot does not open this URL.</p>
      </div>

      <div className="auth-field">
        <label htmlFor="asset-deployment">Deployment context</label>
        <textarea
          id="asset-deployment"
          name="deploymentContext"
          value={values.deploymentContext}
          onChange={(event) => setValues({ ...values, deploymentContext: event.target.value })}
          disabled={readOnly}
          rows={3}
        />
      </div>

      <fieldset className="asset-fieldset" disabled={readOnly}>
        <legend>Owners</legend>
        {values.owners.length === 0 ? <p>No owners assigned.</p> : null}
        <ul className="asset-chip-list">
          {values.owners.map((owner, index) => (
            <li
              key={`${owner.kind}-${owner.kind === 'membership' ? owner.membershipId : owner.teamId}-${index}`}
            >
              <span>{ownerLabel(owner, memberships, teams)}</span>
              {readOnly ? null : (
                <button
                  type="button"
                  onClick={() =>
                    setValues({
                      ...values,
                      owners: values.owners.filter((_, ownerIndex) => ownerIndex !== index),
                    })
                  }
                >
                  Remove owner {ownerLabel(owner, memberships, teams)}
                </button>
              )}
            </li>
          ))}
        </ul>
        {readOnly || values.owners.length >= ASSET_OWNER_MAX_COUNT ? null : (
          <div className="asset-add-row">
            <div className="auth-field">
              <label htmlFor="asset-owner-kind">Owner kind</label>
              <select
                id="asset-owner-kind"
                value={ownerKind}
                onChange={(event) => {
                  setOwnerKind(event.target.value === 'team' ? 'team' : 'membership');
                  setOwnerTargetId('');
                }}
              >
                <option value="membership">Membership</option>
                <option value="team">Team</option>
              </select>
            </div>
            <div className="auth-field">
              <label htmlFor="asset-owner-target">
                {ownerKind === 'membership' ? 'Member' : 'Team'}
              </label>
              <select
                id="asset-owner-target"
                value={ownerTargetId}
                onChange={(event) => setOwnerTargetId(event.target.value)}
              >
                <option value="">Select a target</option>
                {ownerKind === 'membership'
                  ? memberships.map((membership) => (
                      <option key={membership.membershipId} value={membership.membershipId}>
                        {membership.displayName}
                      </option>
                    ))
                  : teams.map((team) => (
                      <option key={team.id} value={team.id}>
                        {team.name}
                      </option>
                    ))}
              </select>
            </div>
            <div className="auth-field">
              <label htmlFor="asset-owner-role">Owner role</label>
              <select
                id="asset-owner-role"
                value={ownerRole}
                onChange={(event) =>
                  setOwnerRole(event.target.value as 'technical' | 'business' | 'security')
                }
              >
                {OWNER_ROLE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              onClick={() => {
                if (ownerTargetId.length === 0) {
                  return;
                }
                const nextOwner: AssetFormOwner =
                  ownerKind === 'membership'
                    ? { kind: 'membership', membershipId: ownerTargetId, role: ownerRole }
                    : { kind: 'team', teamId: ownerTargetId, role: ownerRole };
                setValues({ ...values, owners: [...values.owners, nextOwner] });
                setOwnerTargetId('');
              }}
            >
              Add owner
            </button>
          </div>
        )}
      </fieldset>

      <fieldset className="asset-fieldset" disabled={readOnly}>
        <legend>Tags</legend>
        {values.tags.length === 0 ? <p>No tags.</p> : null}
        <ul className="asset-chip-list">
          {values.tags.map((tag) => (
            <li key={tag}>
              <span>{tag}</span>
              {readOnly ? null : (
                <button
                  type="button"
                  onClick={() =>
                    setValues({ ...values, tags: values.tags.filter((item) => item !== tag) })
                  }
                >
                  Remove tag {tag}
                </button>
              )}
            </li>
          ))}
        </ul>
        {readOnly || values.tags.length >= ASSET_TAG_MAX_COUNT ? null : (
          <div className="asset-add-row">
            <div className="auth-field">
              <label htmlFor="asset-tag-draft">Tag</label>
              <input
                id="asset-tag-draft"
                value={tagDraft}
                onChange={(event) => setTagDraft(event.target.value)}
              />
            </div>
            <button
              type="button"
              onClick={() => {
                const tag = tagDraft.trim();
                if (tag.length === 0 || values.tags.includes(tag)) {
                  setTagDraft('');
                  return;
                }
                setValues({ ...values, tags: [...values.tags, tag] });
                setTagDraft('');
              }}
            >
              Add tag
            </button>
          </div>
        )}
      </fieldset>

      <fieldset className="asset-fieldset" disabled={readOnly}>
        <legend>External identifiers</legend>
        {values.identifiers.length === 0 ? <p>No external identifiers.</p> : null}
        <ul className="asset-chip-list">
          {values.identifiers.map((item) => (
            <li key={`${item.namespace}:${item.identifier}`}>
              <span>
                {item.namespace}: {item.identifier}
              </span>
              {readOnly ? null : (
                <button
                  type="button"
                  onClick={() =>
                    setValues({
                      ...values,
                      identifiers: values.identifiers.filter(
                        (identifier) =>
                          identifier.namespace !== item.namespace ||
                          identifier.identifier !== item.identifier,
                      ),
                    })
                  }
                >
                  Remove identifier {item.namespace} {item.identifier}
                </button>
              )}
            </li>
          ))}
        </ul>
        {readOnly || values.identifiers.length >= ASSET_IDENTIFIER_MAX_COUNT ? null : (
          <div className="asset-add-row">
            <div className="auth-field">
              <label htmlFor="asset-identifier-namespace">Namespace</label>
              <input
                id="asset-identifier-namespace"
                value={identifierNamespace}
                onChange={(event) => setIdentifierNamespace(event.target.value)}
              />
            </div>
            <div className="auth-field">
              <label htmlFor="asset-identifier-value">Identifier</label>
              <input
                id="asset-identifier-value"
                value={identifierValue}
                onChange={(event) => setIdentifierValue(event.target.value)}
              />
            </div>
            <button
              type="button"
              onClick={() => {
                const namespace = identifierNamespace.trim();
                const identifier = identifierValue.trim();
                if (namespace.length === 0 || identifier.length === 0) {
                  return;
                }
                setValues({
                  ...values,
                  identifiers: [...values.identifiers, { namespace, identifier }],
                });
                setIdentifierNamespace('');
                setIdentifierValue('');
              }}
            >
              Add identifier
            </button>
          </div>
        )}
      </fieldset>

      {readOnly ? null : (
        <button type="submit" disabled={submitting} aria-busy={submitting}>
          {submitting
            ? mode === 'create'
              ? 'Creating'
              : 'Saving'
            : mode === 'create'
              ? 'Create asset'
              : 'Save changes'}
        </button>
      )}
    </form>
  );
}

function ownerLabel(
  owner: AssetFormOwner,
  memberships: MembershipOption[],
  teams: TeamOption[],
): string {
  if (owner.kind === 'membership') {
    const membership = memberships.find((item) => item.membershipId === owner.membershipId);
    return `${membership?.displayName ?? 'Member'} (${owner.role})`;
  }
  const team = teams.find((item) => item.id === owner.teamId);
  return `${team?.name ?? 'Team'} (${owner.role})`;
}

function mapAssetError(error: unknown): string {
  if (!isAuthRequestError(error)) {
    return GENERIC_UNAVAILABLE;
  }
  if (error.message === ORGANIZATION_CONTEXT_REQUIRED) {
    return ORGANIZATION_CONTEXT_REQUIRED;
  }
  if (error.status === 401) {
    return GENERIC_SESSION_EXPIRED;
  }
  if (error.status === 403) {
    return GENERIC_ACCESS_DENIED;
  }
  return error.message;
}
