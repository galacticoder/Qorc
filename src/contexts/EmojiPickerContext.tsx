import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { VALID_EMOJI_PICKER_ID } from '../lib/constants';

interface EmojiPickerContextType {
  readonly openPickerId: string | null;
  readonly openPicker: (pickerId: string) => void;
  readonly closePicker: () => void;
  readonly isPickerOpen: (pickerId: string) => boolean;
}

const EmojiPickerContext = createContext<EmojiPickerContextType | undefined>(undefined);

export function EmojiPickerProvider({ children }: { children: React.ReactNode }) {
  const [openPickerId, setOpenPickerId] = useState<string | null>(null);

  const openPicker = useCallback((pickerId: string) => {
    if (!VALID_EMOJI_PICKER_ID.test(pickerId)) {
      return;
    }
    setOpenPickerId(prev => (prev === pickerId ? prev : pickerId));
  }, []);

  const closePicker = useCallback(() => {
    setOpenPickerId(null);
  }, []);

  const contextValue = useMemo(() => ({
    openPickerId,
    openPicker,
    closePicker,
    isPickerOpen: (pickerId: string) => openPickerId === pickerId
  }), [openPickerId, openPicker, closePicker]);

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
