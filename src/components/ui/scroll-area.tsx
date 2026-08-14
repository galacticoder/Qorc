import * as React from 'react';
import { cn } from '@/lib/utils/shared-utils';

const ScrollArea = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => (
  <div ref={ref} className={cn('relative overflow-hidden', className)} {...props}>
    <div
      data-radix-scroll-area-viewport=""
      className="h-full w-full overflow-auto rounded-[inherit]"
      style={{ scrollbarWidth: 'thin' }}
    >
      {children}
    </div>
  </div>
));
ScrollArea.displayName = 'ScrollArea';

const ScrollBar = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { orientation?: 'vertical' | 'horizontal' }
>(() => null);
ScrollBar.displayName = 'ScrollBar';

export { ScrollArea, ScrollBar };
