import type { ComponentProps } from 'react';
import { Icon, type IconName } from './Icon';

/** Standard toolbar hit area and non-shrinking icon; native button props stay intact. */
export function IconButton({
  icon,
  children,
  className = '',
  type = 'button',
  ...props
}: ComponentProps<'button'> & { icon: IconName }) {
  return (
    <button {...props} type={type} className={`icon-button ${className}`}>
      <Icon name={icon} />
      {children}
    </button>
  );
}
