import React, {useState} from "react";
import './Forms.css'

function SignupPage({setIsLogged}){
    const [username, setUsername] = useState();
    const [password, setPassword] = useState();
    const [email, setEmail] = useState();

    const signupClick = () => {
        setUsername(document.getElementById("usrname").value);
        setPassword(document.getElementById("pass").value);
        setEmail(document.getElementById("mail").value);
        const json = {'username': username, 'email': email, 'password': password};
        const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(json)};

        fetchData('http://localhost:5000/register', options).then(data => document.getElementById("msg").textContent = data.Message || data.Error);
        // const ans = await fetchData('http://localhost:5000/register', options);
        // console.log(ans.Message + " " + ans.Error);
        // document.getElementById("msg").textContent = ans.Message || ans.Error;
        // if (ans.Message) {
        //     setIsLogged(true);
        // }
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