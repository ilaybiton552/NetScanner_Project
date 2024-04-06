import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './assets/Navbar';
import ScanPage from './assets/pages/ScanPage';
import NetworkConnection from './assets/pages/NetworkConnection';
import NetworkDetails from './assets/pages/NetworkDetails';

function App() {
  return (
    <Router>
        <Navbar />
        <Routes>
          <Route path="/" element={<Home/>} />
          <Route path="/ScanPage" element={<ScanPage/>} />
          <Route path="/NetworkConnection" element={<NetworkConnection/>} />
          <Route path="/NetworkDetails" element={<NetworkDetails/>}/>
        </Routes>
    </Router>
  )
}

function Home() {
  return (
    <div>
      <h1>Home</h1>
    </div>
  )
}

export default App
