import type { ReactElement } from 'react';

export function AffectedVersionSummary({
  summary,
}: {
  summary: {
    values: readonly string[];
    truncated: boolean;
    omittedDistinctCount: number;
    distinctCount: number;
  };
}): ReactElement {
  return (
    <div>
      <p>Affected versions</p>
      {summary.values.length === 0 ? (
        <p>None listed</p>
      ) : (
        <ul>
          {summary.values.map((version, index) => (
            <li key={`${index}:${version}`}>{version}</li>
          ))}
        </ul>
      )}
      <p>
        {summary.truncated
          ? 'The affected-version summary is truncated.'
          : 'The affected-version summary is complete.'}
      </p>
      <p>Omitted distinct versions: {summary.omittedDistinctCount}</p>
      <p>Distinct affected versions: {summary.distinctCount}</p>
    </div>
  );
}
