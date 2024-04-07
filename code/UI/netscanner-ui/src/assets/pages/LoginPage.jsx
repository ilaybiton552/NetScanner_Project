import React from "react";
import {useNavigate} from "react-router-dom";
import './Forms.css';

function LoginPage({setIsLogged}){
    const navigate = useNavigate();

    const loginClick = () => {
        const username = document.getElementById("username").value;
        const password = document.getElementById("pass").value;
        const json = {'username': username, 'password': password};
        const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(json)};

        fetchData('http://localhost:5000/login', options).then(data => {
            const {Message, Error} = data;
            if (Message) {
                setIsLogged(true);
                navigate("/");
            }
            document.getElementById("msg").textContent = Message || Error});
    }

    return (
        <div className="center">
            <h1>Login Page:</h1>
            <div className="center">
                <p>Username:</p>
                <input id="username"/>
                <p>Password:</p>
                <input id="pass" type="password"/>
                <button onClick={loginClick}>Login</button>
                <p className="top" id="msg"/>
            </div>
        </div>
    )
}

async function fetchData(url, options) {
    try {
        let response = await fetch(url, options);
        const data = await response.json();
        console.log(response);
        return data;
    }
    catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
}

export default LoginPage;