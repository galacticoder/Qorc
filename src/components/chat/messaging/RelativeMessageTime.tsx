import { memo, useEffect, useState } from 'react';
import { formatRelativeAge } from '../../../lib/utils/date-utils';

interface RelativeMessageTimeProps {
  date: Date | number;
  className?: string;
}

export const RelativeMessageTime = memo(function RelativeMessageTime({ date, className }: RelativeMessageTimeProps) {
  const timestamp = date instanceof Date ? date.getTime() : date;
  const [now, setNow] = useState(Date.now);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const update = () => {
      clearTimeout(timer);
      const current = Date.now();
      setNow(current);
      if (!Number.isFinite(timestamp) || document.visibilityState === 'hidden') return;
      const age = current - timestamp;
      if (age >= 7 * 86_400_000) return;
      const unit = age < 3_600_000 ? 60_000 : age < 86_400_000 ? 3_600_000 : 86_400_000;
      timer = setTimeout(update, age < 0 ? Math.min(-age, 60_000) : unit - age % unit);
    };
    update();
    document.addEventListener('visibilitychange', update);
    window.addEventListener('focus', update);
    return () => {
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', update);
      window.removeEventListener('focus', update);
    };
  }, [timestamp]);

  return <span className={className}>{formatRelativeAge(timestamp, now)}</span>;
});
