import React, {useState} from 'react';
import { Link, NavLink } from 'react-router-dom';
import "./Navbar.css"

function Navbar({isLogged}) {
  return (
    <nav>
      <Link to="/" className='title'>Home</Link>
      {isLogged ? (<ul>
        <li>
          <NavLink to="/ScanPage">Scan</NavLink>
        </li>
        <li>
          <NavLink to="/NetworkConnection">Connect to Network</NavLink>
        </li>
        <li>
          <NavLink to="/NetworkDetails">Network Details</NavLink>
        </li>
        <li>
          <NavLink to="/AttacksPage">Attacks</NavLink>
        </li>
        <li>
          <NavLink to="/BlockedDevices">Blocked Devices</NavLink>
        </li>
        <li>
          <NavLink to="/Logout">Logout</NavLink>
        </li>
        </ul>) : (<ul>
          <li>
          <NavLink to="/LoginPage">Login</NavLink>
        </li>
        <li>
          <NavLink to="/SignupPage">Sign Up</NavLink>
        </li>
        </ul>)}
      <br/>
    </nav>
  )
}

export default Navbar;