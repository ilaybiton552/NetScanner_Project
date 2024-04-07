import React from "react";
import './Forms.css'

function SignupPage({setIsLogged}){
    const signupClick = () => {
        const username = document.getElementById("usrname").value;
        const password = document.getElementById("pass").value;
        const email = document.getElementById("mail").value;
        const json = {'username': username, 'email': email, 'password': password};
        const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(json)};

        fetchData('http://localhost:5000/register', options).then(data => {
            const {Message, Error} = data;
            if (Message) {
                setIsLogged(true);
            }
            document.getElementById("msg").textContent = Message || Error});
    }

    return (
        <div className="center">
            <h1>Sign Up Page:</h1>
            <div className="center">
                <p>Username:</p>
                <input id="usrname"/>
                <p>Password:</p>
                <input id="pass" type="password"/>
                <p>Email:</p>
                <input id="mail"/>
                <button onClick={signupClick}>Sign up</button>
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

export default SignupPage;