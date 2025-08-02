import React from 'react';
import Navbar from './layout/Navbar';
import HeroSection from './sections/HeroSection';
import SecuritySection from './sections/SecuritySection';
import FeaturesSection from './sections/FeaturesSection';
import TechnologySection from './sections/TechnologySection';
import CTASection from './sections/CTASection';
import FooterSection from './sections/FooterSection';

interface HomeScreenProps {
  onNavigate: (page: 'home' | 'server' | 'chat') => void;
}

const HomeScreen: React.FC<HomeScreenProps> = ({ onNavigate }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-indigo-50/50 relative overflow-hidden">
      <Navbar onNavigate={onNavigate} />
      <HeroSection onNavigate={onNavigate} />
      <SecuritySection />
      <FeaturesSection />
      <TechnologySection />
      <CTASection onNavigate={onNavigate} />
      <FooterSection />
    </div>
  );
};

export default HomeScreen;