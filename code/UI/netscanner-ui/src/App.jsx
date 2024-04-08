import { useState, useEffect } from 'react'
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
  const [username, setUsername] = useState("guest");

  return (
    <Router>
        <Navbar isLogged={isLogged} />
        <Routes>
          <Route path="/" element={<Home username={username}/>} />
          <Route path="/ScanPage" element={<ScanPage/>} />
          <Route path="/NetworkConnection" element={<NetworkConnection/>} />
          <Route path="/NetworkDetails" element={<NetworkDetails/>}/>
          <Route path="/AttacksPage" element={<AttacksPage username={username}/>}/>
          <Route path="/LoginPage" element={<LoginPage setIsLogged={setIsLogged} setUsername={setUsername}/>}/>
          <Route path="/SignupPage" element={<SignupPage setIsLogged={setIsLogged} setUsername={setUsername}/>}/>
          <Route path="/Logout" element={<Logout setIsLogged={setIsLogged} setUsername={setUsername}/>}/>
        </Routes>
    </Router>
  )
}

function Home({username}) {
  const [attacks, setAttacks] = useState([]);

  useEffect(() => {
  const fetchAttacks = async () => {
    try {
        const attacksData = await fetchData('http://localhost:5000/all_attacks', null);
        setAttacks(attacksData);
    } catch (error) {
        console.error('Error fetching attacks:', error);
    }
    };
    fetchAttacks();
  },[])

  return (
    <div className='center'>
      <h1>Hello {username}</h1>
      {Array.isArray(attacks) ? (attacks.map((attack) => (
        <div>
          <h1>{attack.attack_name}</h1>
          <p>{attack.attack_description}</p>
        </div>
      ))) : (<p>Loading...</p>)}
      
    </div>

  )
}

async function fetchData(url, options) {
  try {
      let response = await fetch(url, options);
      const data = await response.json();
      console.log(data);
      return data;
  }
  catch (error) {
      console.error('Error fetching data:', error);
      throw error;
  }
}

export default App
