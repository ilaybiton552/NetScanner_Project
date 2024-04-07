import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './assets/Navbar';
import ScanPage from './assets/pages/ScanPage';
import NetworkConnection from './assets/pages/NetworkConnection';
import NetworkDetails from './assets/pages/NetworkDetails';
import AttacksPage from './assets/pages/AttacksPage';
import LoginPage from './assets/pages/LoginPage';
import SignupPage from './assets/pages/SignupPage';
import Logout from './assets/pages/Logout';

function App() {
  const [isLogged, setIsLogged] = useState(false);
  const [username, setUsername] = useState();

  return (
    <Router>
        <Navbar isLogged={isLogged} />
        <Routes>
          <Route path="/" element={<Home/>} />
          <Route path="/ScanPage" element={<ScanPage/>} />
          <Route path="/NetworkConnection" element={<NetworkConnection/>} />
          <Route path="/NetworkDetails" element={<NetworkDetails/>}/>
          <Route path="/AttacksPage" element={<AttacksPage username={username}/>}/>
          <Route path="/LoginPage" element={<LoginPage setIsLogged={setIsLogged} setUsername={setUsername}/>}/>
          <Route path="/SignupPage" element={<SignupPage setIsLogged={setIsLogged} setUsername={setUsername}/>}/>
          <Route path="/Logout" element={<Logout setIsLogged={setIsLogged}/>}/>
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
