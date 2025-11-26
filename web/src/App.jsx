import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import DeviceAgentPanel from './components/DeviceAgentPanel';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/app" element={<DeviceAgentPanel />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
