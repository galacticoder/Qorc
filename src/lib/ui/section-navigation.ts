import { createContext } from 'react';

export type SectionNavigationMotion = { index: number; phase: 'dragging' | 'settling' };
export const SectionNavigationContext = createContext<((motion: SectionNavigationMotion | null) => void) | null>(null);
