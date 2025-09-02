import React from "react";

interface ProgressBarProps {
  progress: number; // 0 to 1
}

export function ProgressBar({ progress }: ProgressBarProps) {
  return (
    <div className="w-full bg-gray-300 rounded h-1.5 overflow-hidden" style={{ marginBottom: 2 }}>
      <div
        className="bg-blue-500 h-1.5 rounded transition-all duration-300"
        style={{ width: `${(progress * 100).toFixed(2)}%` }}
      />
    </div>
  );
}