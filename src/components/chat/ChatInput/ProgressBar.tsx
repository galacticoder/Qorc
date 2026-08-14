import { useMemo } from "react";

interface ProgressBarProps {
  readonly progress: number;
  readonly indeterminate?: boolean;
}

export function ProgressBar({ progress, indeterminate = false }: ProgressBarProps) {
  const progressPercent = useMemo(() => {
    const clamped = Math.max(0, Math.min(1, progress));
    return (clamped * 100).toFixed(2);
  }, [progress]);

  return (
    <div className="w-full bg-gray-300 rounded h-1.5 overflow-hidden" style={{ marginBottom: 2 }}>
      <div
        className={indeterminate
          ? "qor-file-progress-indeterminate bg-blue-500 h-1.5 rounded"
          : "bg-blue-500 h-1.5 rounded transition-all duration-300"}
        style={{ width: indeterminate ? '35%' : `${progressPercent}%` }}
        role="progressbar"
        aria-valuenow={indeterminate ? undefined : Math.round(Number(progressPercent))}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuetext={indeterminate ? 'Encrypted transfer in progress' : undefined}
      />
    </div>
  );
}
