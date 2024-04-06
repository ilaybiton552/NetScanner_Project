import React from 'react';
import { Link, NavLink } from 'react-router-dom';
import "./Navbar.css"

function Navbar() {
  return (
    <nav>
      <Link to="/" className='title'>Home</Link>
      <ul>
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
          <NavLink to="/LoginPage">Login</NavLink>
        </li>
        <li>
          <NavLink to="/SignupPage">Sign Up</NavLink>
        </li>
      </ul>
      <br/>
    </nav>
  )
}

export default Navbar;