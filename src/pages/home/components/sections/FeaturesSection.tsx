import React from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { features } from '../../config/features.tsx';

const FeaturesSection: React.FC = () => {
  return (
    <div id="features" className="py-16 dark:bg-gray-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4 animate-fade-in-up">
            Powerful Features
          </h2>
          <p className="text-lg text-gray-600 dark:text-gray-300 max-w-2xl mx-auto animate-fade-in-up" style={{ animationDelay: '200ms' }}>
            Everything you need for secure communication, built with modern web technologies
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <Card 
              key={index} 
              className="group hover:shadow-2xl transition-all duration-500 border-2 hover:border-transparent relative overflow-hidden transform hover:-translate-y-2 animate-fade-in-up bg-white/70 dark:bg-gray-800/70 backdrop-blur-sm dark:border-gray-700"
              style={{ animationDelay: `${index * 100}ms` }}
            >
              <div className={`absolute inset-0 bg-gradient-to-r ${feature.color} opacity-0 group-hover:opacity-10 dark:group-hover:opacity-20 transition-opacity duration-500`} />
              <CardHeader className="relative z-10">
                <div className="flex items-center justify-between mb-2">
                  <div className={`p-3 rounded-xl bg-gradient-to-r ${feature.color} text-white transform group-hover:scale-110 transition-all duration-300 shadow-lg`}>
                    {feature.icon}
                  </div>
                  <Badge 
                    variant="secondary" 
                    className="text-xs group-hover:bg-white dark:group-hover:bg-gray-700 group-hover:text-gray-800 dark:group-hover:text-white transition-all duration-300 dark:bg-gray-700 dark:text-gray-200"
                  >
                    {feature.highlight}
                  </Badge>
                </div>
                <CardTitle className="text-xl group-hover:text-gray-900 dark:group-hover:text-white transition-colors duration-300 dark:text-gray-100">
                  {feature.title}
                </CardTitle>
              </CardHeader>
              <CardContent className="relative z-10">
                <CardDescription className="text-base group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors duration-300 dark:text-gray-400">
                  {feature.description}
                </CardDescription>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
};

export default FeaturesSection;