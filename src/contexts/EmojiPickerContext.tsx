import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { VALID_EMOJI_PICKER_ID } from '../lib/constants';

export interface EmojiPickerOrigin {
  readonly top: number;
  readonly left: number;
}

interface EmojiPickerContextType {
  readonly openPickerId: string | null;
  readonly openPickerOrigin: EmojiPickerOrigin | null;
  readonly openPicker: (pickerId: string, origin?: EmojiPickerOrigin) => void;
  readonly closePicker: () => void;
  readonly isPickerOpen: (pickerId: string) => boolean;
}

const EmojiPickerContext = createContext<EmojiPickerContextType | undefined>(undefined);

export function EmojiPickerProvider({ children }: { children: React.ReactNode }) {
  const [pickerState, setPickerState] = useState<{
    readonly id: string;
    readonly origin: EmojiPickerOrigin | null;
  } | null>(null);
  const openPickerId = pickerState?.id ?? null;
  const openPickerOrigin = pickerState?.origin ?? null;

  const openPicker = useCallback((pickerId: string, origin?: EmojiPickerOrigin) => {
    if (!VALID_EMOJI_PICKER_ID.test(pickerId)) {
      return;
    }

    const nextOrigin = origin && Number.isFinite(origin.top) && Number.isFinite(origin.left)
      ? { top: origin.top, left: origin.left }
      : null;
    setPickerState((previous) => {
      if (
        previous?.id === pickerId &&
        previous.origin?.top === nextOrigin?.top &&
        previous.origin?.left === nextOrigin?.left
      ) {
        return previous;
      }
      return { id: pickerId, origin: nextOrigin };
    });
  }, []);

  const closePicker = useCallback(() => {
    setPickerState(null);
  }, []);

  const contextValue = useMemo(() => ({
    openPickerId,
    openPickerOrigin,
    openPicker,
    closePicker,
    isPickerOpen: (pickerId: string) => openPickerId === pickerId
  }), [openPickerId, openPickerOrigin, openPicker, closePicker]);

  return (
    <EmojiPickerContext.Provider value={contextValue}>
      {children}
    </EmojiPickerContext.Provider>
  );
}

export function useEmojiPicker() {
  const context = useContext(EmojiPickerContext);
  if (context === undefined) {
    throw new Error('Context not available');
  }
  return context;
}
