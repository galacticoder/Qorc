import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { frontendTechnologies, backendTechnologies, technologyHighlights } from '../../config/features';
import { RocketIcon, CheckIcon } from '@radix-ui/react-icons';

type TechType = 'frontend' | 'backend';

interface Technology {
  name: string;
  desc: string;
  version: string;
  type: TechType;
}

const InfiniteTechBanner = ({ items }: { items: Technology[] }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const animationRef = useRef<number>();
  const [scrollPosition, setScrollPosition] = useState(0);
  const [contentWidth, setContentWidth] = useState(0);

  useEffect(() => {
    if (contentRef.current) {
      setContentWidth(contentRef.current.scrollWidth);
    }
  }, [items]);

  useEffect(() => {
    if (!contentWidth) return;

    let animationId: number;
    let lastTimestamp = 0;
    const speed = 0.6;

    const animate = (timestamp: number) => {
      if (!lastTimestamp) lastTimestamp = timestamp;
      const delta = timestamp - lastTimestamp;
      lastTimestamp = timestamp;

      setScrollPosition(prev => {
        const newPos = (prev + speed * (delta / 16)) % contentWidth;
        return newPos;
      });

      animationId = requestAnimationFrame(animate);
    };

    animationId = requestAnimationFrame(animate);
    animationRef.current = animationId;

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, [contentWidth]);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.style.transform = `translateX(-${scrollPosition}px)`;
    }
  }, [scrollPosition]);

  const pauseAnimation = () => {
    if (animationRef.current) {
      cancelAnimationFrame(animationRef.current);
    }
  };

  const resumeAnimation = () => {
    let lastTimestamp = 0;
    const speed = 1;

    const animate = (timestamp: number) => {
      if (!lastTimestamp) lastTimestamp = timestamp;
      const delta = timestamp - lastTimestamp;
      lastTimestamp = timestamp;

      setScrollPosition(prev => {
        const newPos = (prev + speed * (delta / 16)) % contentWidth;
        return newPos;
      });

      animationRef.current = requestAnimationFrame(animate);
    };

    animationRef.current = requestAnimationFrame(animate);
  };

  return (
    <div 
      className="relative w-full overflow-hidden py-8"
      onMouseEnter={pauseAnimation}
      onMouseLeave={resumeAnimation}
    >
      <div 
        ref={containerRef}
        className="flex whitespace-nowrap will-change-transform"
      >
        <div ref={contentRef} className="inline-flex items-center gap-4 pr-4">
          {[...items, ...items].map((tech, index) => (
            <TechPill 
              key={`${tech.name}-${tech.type}-${index}`}
              tech={tech}
            />
          ))}
        </div>
      </div>
      <div className="absolute inset-0 pointer-events-none bg-gradient-to-r from-white via-transparent to-white dark:from-gray-900 dark:via-transparent dark:to-gray-900" />
    </div>
  );
};

const TechPill = ({ tech }: { tech: Technology }) => {
  const [isHovered, setIsHovered] = useState(false);
  const icon = getTechIcon(tech.name);

  return (
    <div 
      className={`relative flex items-center p-3 rounded-xl bg-white/90 dark:bg-gray-800/90 border border-gray-200/60 dark:border-gray-700/60 shadow-sm transition-all duration-200 ${
        isHovered ? 'shadow-md scale-105 z-10' : ''
      }`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="w-6 h-6 flex items-center justify-center mr-2">
        {icon}
      </div>
      <div className="flex flex-col">
        <Badge 
          variant="outline" 
          className={`text-sm font-medium px-2 py-0.5 mb-1 w-fit ${
            tech.type === 'frontend' 
              ? 'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-900/30 dark:text-blue-300' 
              : 'border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-900/30 dark:text-green-300'
          }`}
        >
          {tech.name}
        </Badge>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          {tech.version}
        </span>
      </div>
      {isHovered && (
        <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-3 px-3 py-2 text-sm bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 max-w-xs">
          <p className="font-medium mb-1">{tech.name}</p>
          <p className="text-xs text-gray-600 dark:text-gray-300">{tech.desc}</p>
        </div>
      )}
    </div>
  );
};

function getTechIcon(techName: string): React.ReactNode {
  const iconClass = "w-full h-full";
  const tech = techName.split(' ')[0];
  
  if (tech === 'React') return <div className={`${iconClass} text-[#61DAFB]`}>⚛️</div>;
  if (tech === 'TypeScript') return <div className={`${iconClass} text-[#3178C6]`}>TS</div>;
  if (tech === 'Vite') return <div className={`${iconClass} text-[#646CFF]`}>⚡</div>;
  if (tech === 'Node.js') return <div className={`${iconClass} text-[#339933]`}>⬢</div>;
  if (tech === 'WebSocket') return <div className={`${iconClass} text-yellow-500`}>🔌</div>;
  if (tech === 'Redis') return <div className={`${iconClass} text-[#D82C20]`}>🗃️</div>;//get pics later when focused on the ui
  if (tech === 'Tailwind') return <div className={`${iconClass} text-[#06B6D4]`}>🌀</div>;
  return <div className={`${iconClass} text-gray-500`}>🛠️</div>;
}

const TechnologySection: React.FC = () => {
  const frontendTech: Technology[] = frontendTechnologies.map(tech => ({
    ...tech,
    type: 'frontend' as const
  }));

  const backendTech: Technology[] = backendTechnologies.map(tech => ({
    ...tech,
    type: 'backend' as const
  }));

  const allTechItems = [...frontendTech, ...backendTech];

  return (
    <div id="technology" className="py-20 bg-white/60 dark:bg-gray-900/60 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <h2 className="text-5xl font-bold text-gray-900 dark:text-white mb-6">
            Technology Stack
          </h2>
          <p className="text-xl text-gray-600 dark:text-gray-300 max-w-3xl mx-auto">
            Used in this project
          </p>
        </div>

        <div className="relative -mx-8">
          <InfiniteTechBanner items={allTechItems} />
        </div>

        <div className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-8">
          {technologyHighlights.map((item, index) => (
            <Card 
              key={index} 
              className="text-center border border-gray-200/50 dark:border-gray-700/50 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm"
            >
              <CardContent className="p-8">
                <div className={`w-14 h-14 mx-auto mb-6 rounded-xl bg-gradient-to-r ${item.color} flex items-center justify-center text-white`}>
                  {item.icon}
                </div>
                <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">{item.title}</h3>
                <div className="space-y-4">
                  {item.stats.map((stat, idx) => (
                    <div key={idx} className="flex justify-between items-center">
                      <span className="text-gray-600 dark:text-gray-400">{stat.label}</span>
                      <span className="font-bold text-gray-900 dark:text-white">{stat.value}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="mt-16 text-center text-gray-500 dark:text-gray-400">
          Hover over any technology to see details
        </div>
      </div>
    </div>
  );
};

export default TechnologySection;