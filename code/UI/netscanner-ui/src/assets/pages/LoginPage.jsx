import React from "react";
import './Forms.css'

function LoginPage({setIsLogged}){
    const [username, setUsername] = useState();
    const [password, setPassword] = useState();

    const loginClick = () => {
        setUsername(document.getElementById("usrname").value);
        setPassword(document.getElementById("pass").value);
        const json = {'username': username, 'password': password};
        const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(json)};

        const ans = fetchData('http://localhost:5000/login', options);
        document.getElementById("msg").textContent = ans.Message || ans.Error;
        if (ans.Message) {
            setIsLogged(true);
        }
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
            </div>
            <p id="msg"/>
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