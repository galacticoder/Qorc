import React, { useMemo } from "react";

interface ProgressBarProps {
  readonly progress: number;
}

export function ProgressBar({ progress }: ProgressBarProps) {
  const progressPercent = useMemo(() => {
    const clamped = Math.max(0, Math.min(1, progress));
    return (clamped * 100).toFixed(2);
  }, [progress]);

  return (
    <div className="w-full bg-gray-300 rounded h-1.5 overflow-hidden" style={{ marginBottom: 2 }}>
      <div
        className="bg-blue-500 h-1.5 rounded transition-all duration-300"
        style={{ width: `${progressPercent}%` }}
        role="progressbar"
        aria-valuenow={Math.round(Number(progressPercent))}
        aria-valuemin={0}
        aria-valuemax={100}
      />
    </div>
  );
}
