import type { ReactNode } from 'react';

/** Shared, non-interactive tag treatment for note tags and notification labels. */
export function Tag({
  children,
  tone = 'default',
  title,
}: {
  children: ReactNode;
  tone?: 'default' | 'low' | 'moderate' | 'high' | 'critical' | 'muted';
  title?: string;
}) {
  return (
    <span className={`app-tag app-tag--${tone}`} title={title}>
      {children}
    </span>
  );
}
