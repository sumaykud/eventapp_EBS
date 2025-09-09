import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Landing from './pages/Landing';
import './App.css';

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/" element={<Landing />} />
          {/* Add more routes here as needed */}
          <Route path="/login" element={<div className="p-8 text-center">Login Page - Coming Soon</div>} />
          <Route path="/register" element={<div className="p-8 text-center">Register Page - Coming Soon</div>} />
          <Route path="/events" element={<div className="p-8 text-center">Events Page - Coming Soon</div>} />
        </Routes>
      </div>
    </Router>
  )
}

export default App
