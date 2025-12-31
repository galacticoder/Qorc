import { format, isToday, isYesterday, isThisYear } from 'date-fns';

/**
 * Format a date as relative age string (now, Xm, Xh, Xd, or MM/DD/YY).
 */
export const formatRelativeAge = (date: Date | number | undefined): string => {
  if (date === undefined || date === null) return '';

  const dateObj = typeof date === 'number' ? new Date(date) : date;
  if (!(dateObj instanceof Date) || isNaN(dateObj.getTime())) {
    return '';
  }

  const now = new Date();
  const diff = now.getTime() - dateObj.getTime();

  if (diff < 0) return '';

  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return 'now';
  if (minutes < 60) return `${minutes}m`;
  if (hours < 24) return `${hours}h`;
  if (days < 7) return `${days}d`;

  const month = (dateObj.getMonth() + 1).toString().padStart(2, '0');
  const day = dateObj.getDate().toString().padStart(2, '0');
  const year = dateObj.getFullYear().toString().slice(-2);
  return `${month}/${day}/${year}`;
};

/**
 * Format call duration from seconds to human-readable string (Xhr Xm Xs).
 */
export const formatCallDurationSeconds = (seconds?: number): string => {
  if (!seconds) return '';

  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}hr ${mins}m ${secs}s`;
  } else if (mins > 0) {
    return `${mins}m ${secs}s`;
  } else {
    return `${secs}s`;
  }
};

/**
 * Format call duration from milliseconds to M:SS format.
 */
export const formatCallDurationMs = (duration?: number): string => {
  if (!duration) return '';
  const mins = Math.floor(duration / 60000);
  const secs = Math.floor((duration % 60000) / 1000);
  return `${mins}:${secs.toString().padStart(2, '0')}`;
};

/**
 * Format timestamp for call history: time if today, short date otherwise.
 */
export const formatCallHistoryTime = (timestamp?: number): string => {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  const now = new Date();
  const isSameDay = date.toDateString() === now.toDateString();

  if (isSameDay) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
};

/**
 * Format message timestamp for chat display with context-aware output.
 * today/yesterday/this year/other year formatting.
 */
export const formatMessageTimestamp = (timestamp: Date): string => {
  try {
    if (!(timestamp instanceof Date) || isNaN(timestamp.getTime())) {
      return '';
    }
    // Today: show time only
    if (isToday(timestamp)) {
      return format(timestamp, 'h:mm a');
    }
    // Yesterday: prefix
    if (isYesterday(timestamp)) {
      return `Yesterday ${format(timestamp, 'h:mm a')}`;
    }
    // This year: Month day, time
    if (isThisYear(timestamp)) {
      return format(timestamp, 'MMM d, h:mm a');
    }
    // Other years: include year
    return format(timestamp, 'MMM d, yyyy, h:mm a');
  } catch {
    return '';
  }
};

/**
 * Format time for message receipts.
 * locale-aware time format.
 */
export const formatReceiptTime = (date: Date | undefined): string | undefined => {
  if (!date || !(date instanceof Date) || isNaN(date.getTime())) {
    return undefined;
  }
  try {
    return format(date, 'p');
  } catch {
    return undefined;
  }
};
