import React, { useState } from 'react';
import HomeScreen from './pages/home/components/HomeScreen.tsx';
import ServerConnection from './pages/ServerConnection.tsx';
import ChatApp from './pages/Index.tsx';

type Page = 'home' | 'server' | 'chat';

function App() {
  const [currentPage, setCurrentPage] = useState<Page>('home');

  const renderPage = () => {
    return <ChatApp onNavigate={setCurrentPage}/>;
    // switch (currentPage) {
    //   case 'home':
    //     return <HomeScreen onNavigate={setCurrentPage} />;
    //   case 'server':
    //     return <ServerConnection onNavigate={setCurrentPage} />;
    //   case 'chat':
    //     return <ChatApp onNavigate={setCurrentPage}/>;
    //   default:
    //     return <HomeScreen onNavigate={setCurrentPage} />;
    // }
  };

  return (
    <div className="App">
      {renderPage()}
    </div>
  );
}

export default App;
