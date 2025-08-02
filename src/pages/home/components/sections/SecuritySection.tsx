import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { LockClosedIcon, CheckIcon } from '@radix-ui/react-icons';
import { securitySpecs } from '../../config/features';
import { securityPromises } from '../../config/navigation.tsx';

const SecuritySection: React.FC = () => {
  return (
    <div id="security" className="py-24 bg-white/60 dark:bg-gray-900/60 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-20">
          <h2 className="text-5xl md:text-6xl font-bold text-gray-900 dark:text-white mb-6 animate-fade-in-up">
            Unbreakable Security
          </h2>
          <p className="text-xl md:text-2xl text-gray-600 dark:text-gray-300 max-w-3xl mx-auto animate-fade-in-up leading-relaxed" style={{ animationDelay: '200ms' }}>
            Built with industry-standard cryptographic algorithms and security best practices.
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 mb-16">
          {securitySpecs.map((spec, index) => (
            <Card 
              key={index} 
              className="border-2 border-gray-200/50 dark:border-gray-700/50 hover:border-blue-300 dark:hover:border-blue-500 transition-all duration-500 hover:shadow-2xl dark:hover:shadow-gray-800/50 transform hover:-translate-y-2 animate-fade-in-up bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm group"
              style={{ animationDelay: `${index * 100}ms` }}
            >
              <CardContent className="p-8">
                <div className="flex justify-between items-start mb-4">
                  <span className="font-bold text-lg text-gray-800 dark:text-gray-100">{spec.label}</span>
                  <Badge 
                    variant="outline" 
                    className="font-mono text-sm hover:bg-blue-50 dark:hover:bg-gray-700 transition-colors duration-300 group-hover:border-blue-500 dark:group-hover:border-blue-400 dark:border-gray-600 dark:text-gray-300"
                  >
                    {spec.value}
                  </Badge>
                </div>
                <p className="text-gray-600 dark:text-gray-400 text-sm leading-relaxed">{spec.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="bg-gradient-to-r from-green-50 via-emerald-50 to-green-50 dark:from-green-900/20 dark:via-emerald-900/20 dark:to-green-900/20 rounded-3xl p-12 border-2 border-green-200/50 dark:border-green-800/30 hover:shadow-2xl dark:hover:shadow-green-900/30 transition-all duration-500 transform hover:scale-[1.02] backdrop-blur-sm">
          <div className="flex items-center justify-center mb-8">
            <div className="p-4 bg-green-500 dark:bg-green-600 rounded-2xl mr-4">
              <LockClosedIcon className="h-10 w-10 text-white animate-pulse" />
            </div>
            <h3 className="text-4xl font-bold text-green-800 dark:text-green-200">Security Promise</h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-green-700 dark:text-green-300">
            {securityPromises.map((promise, index) => (
              <div 
                key={promise}
                className="flex items-center animate-fade-in-left text-lg"
                style={{ animationDelay: `${index * 150}ms` }}
              >
                <CheckIcon className="h-6 w-6 mr-4 text-green-600 dark:text-green-400 flex-shrink-0" />
                <span>{promise}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecuritySection;