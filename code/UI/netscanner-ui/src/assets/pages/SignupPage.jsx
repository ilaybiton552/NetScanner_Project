import React from "react";
import './Forms.css'

function SignupPage(){
    return (
        <div className="center">
            <h1>Sign Up Page:</h1>
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