import React from 'react';
import { Button } from '@/components/ui/button';
import { callToActionButtons } from '../../config/navigation.tsx';

interface CTASectionProps {
  onNavigate: (page: 'home' | 'server' | 'chat') => void;
}

const CTASection: React.FC<CTASectionProps> = ({ onNavigate }) => {
  return (
    <div className="py-24 bg-gradient-to-br from-blue-600/10 via-purple-600/10 to-indigo-600/10 dark:from-blue-900/20 dark:via-purple-900/20 dark:to-indigo-900/20 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-r from-blue-600/5 to-purple-600/5 dark:from-blue-900/10 dark:to-purple-900/10 animate-pulse" />
      <div className="max-w-5xl mx-auto text-center px-4 sm:px-6 lg:px-8 relative z-10">
        <h2 className="text-5xl md:text-6xl font-bold text-gray-900 dark:text-gray-100 mb-8 animate-fade-in-up">
          Ready to chat or host?
        </h2>
        <p className="text-xl md:text-2xl text-gray-600 dark:text-gray-300 mb-6 max-w-3xl mx-auto animate-fade-in-up leading-relaxed" style={{ animationDelay: '200ms' }}>
          Start using military-grade encryption for your conversations.
        </p>
        <p className="text-lg text-gray-500 dark:text-gray-400 mb-12 max-w-2xl mx-auto animate-fade-in-up" style={{ animationDelay: '400ms' }}>
          Never stores your messages.
        </p>
        
        <div className="flex flex-col sm:flex-row gap-6 justify-center items-center mb-12 animate-fade-in-up" style={{ animationDelay: '600ms' }}>
          {callToActionButtons.map((btn, idx) => (
            <Button
              key={idx}
              onClick={() => btn.action(onNavigate)}
              size="lg"
              variant={btn.variant === 'outline' ? 'outline' : 'default'}
              className={
                btn.variant === 'primary'
                  ? 'text-xl px-12 py-6 bg-gradient-to-r from-blue-600 via-purple-600 to-blue-700 hover:from-blue-700 hover:via-purple-700 hover:to-blue-800 text-white dark:text-white/90 shadow-2xl hover:shadow-3xl transform hover:scale-110 transition-all duration-500 rounded-2xl'
                  : 'text-xl px-12 py-6 border-3 border-gray-300 dark:border-gray-600 hover:border-blue-500 dark:hover:border-blue-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-gray-800/50 transform hover:scale-110 transition-all duration-500 rounded-2xl text-gray-700 dark:text-gray-300'
              }
            >
              {btn.iconLeft}
              {btn.label}
              {btn.iconRight}
            </Button>
          ))}
        </div>

        <p className="text-sm text-gray-500 dark:text-gray-500/80 mt-12 animate-fade-in-up" style={{ animationDelay: '1000ms' }}>
          Open source • MIT License • No data collection • No backdoors • SOC 2 Compliant
        </p>
      </div>
    </div>
  );
};

export default CTASection;