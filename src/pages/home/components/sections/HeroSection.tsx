import React, { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { RocketIcon } from '@radix-ui/react-icons';
import { EncryptionIcon } from '@/components/chat/icons';
import { heroButtons, heroBadges } from '../../config/navigation.tsx';

interface HeroSectionProps {
  onNavigate: (page: 'home' | 'server' | 'chat') => void;
}

const HeroSection: React.FC<HeroSectionProps> = ({ onNavigate }) => {
  const [isVisible, setIsVisible] = useState(false);
  const heroRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  return (
    <div ref={heroRef} className="relative overflow-hidden pt-20 dark:bg-gray-900/50">
      <div className="absolute inset-0 bg-gradient-to-br from-blue-600/10 to-indigo-600/10 dark:from-blue-900/20 dark:to-indigo-900/20" />
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-32">
        <div className="text-center">
          {/* floating icon */}
          <div 
            className={`mx-auto w-32 h-32 rounded-3xl bg-gradient-to-r from-blue-600 to-blue-700 flex items-center justify-center mb-12 transform transition-all duration-1500 ${
              isVisible ? 'scale-100 rotate-0 opacity-100' : 'scale-0 rotate-180 opacity-0'
            }`}
            style={{ 
              boxShadow: '0 25px 80px rgba(59, 130, 246, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.1)',
              animation: 'float 4s ease-in-out infinite'
            }}
          >
            <EncryptionIcon className="h-16 w-16 text-white" />
            <div className="absolute -top-2 -right-2 w-8 h-8 bg-green-500 rounded-full border-4 border-white flex items-center justify-center">
              <RocketIcon className="h-4 w-4 text-white" />
            </div>
          </div>
          
          {/* title */}
          <h1 
            className={`text-6xl md:text-8xl font-black mb-8 transform transition-all duration-1500 delay-300 ${
              isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'
            }`}
          >
            <span className="bg-gradient-to-r from-gray-900 to-blue-900 dark:from-gray-100 dark:to-blue-200 bg-clip-text text-transparent">
              Secure
            </span>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-blue-700 animate-pulse">
              Chat
            </span>
          </h1>
          
          {/* subtitle */}
          <p 
            className={`text-2xl md:text-3xl text-gray-700 dark:text-gray-300 mb-6 max-w-4xl mx-auto font-medium leading-relaxed transform transition-all duration-1500 delay-200 ${
              isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'
            }`}
          >
            Military-grade end-to-end encrypted messaging that puts privacy before anything.
          </p>
          
          <p 
            className={`text-lg md:text-xl text-gray-600 dark:text-gray-400 mb-12 max-w-3xl mx-auto transform transition-all duration-1500 delay-300 ${
              isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'
            }`}
          >
            No backdoors, no data collection, no compromises.
          </p>
          
          {/* cta buttons */}
          <div className="flex flex-col sm:flex-row gap-6 justify-center items-center mb-16">
            {heroButtons.map((btn, idx) => (
              <Button
                key={idx}
                onClick={() => btn.action(onNavigate)}
                size="lg"
                variant={btn.variant === 'outline' ? 'outline' : 'default'}
                className={
                  btn.variant === 'primary'
                    ? 'text-xl px-12 py-6 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white dark:text-white/90 shadow-2xl hover:shadow-3xl transform hover:scale-110 transition-all duration-500 rounded-2xl'
                    : 'text-xl px-12 py-6 border-3 border-gray-300 dark:border-gray-600 hover:border-blue-500 dark:hover:border-blue-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-gray-800/50 transform hover:scale-110 transition-all duration-500 rounded-2xl text-gray-700 dark:text-gray-300'
                }
              >
                {btn.iconLeft}
                {btn.label}
                {btn.iconRight}
              </Button>
            ))}
          </div>
          
          {/* badges */}
          <div 
            className={`flex flex-wrap justify-center gap-4 transform transition-all duration-1500 delay-1100 ${
              isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'
            }`}
          >
            {heroBadges.map((badge, index) => (
              <Badge 
                key={badge.text}
                variant="secondary" 
                className="text-base px-6 py-3 hover:bg-blue-100 dark:hover:bg-gray-700 hover:text-blue-700 dark:hover:text-white transition-all duration-300 cursor-pointer transform hover:scale-110 rounded-xl flex items-center gap-2 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700"
                style={{ animationDelay: `${index * 100}ms` }}
              >
                {badge.icon}
                {badge.text}
              </Badge>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default HeroSection;