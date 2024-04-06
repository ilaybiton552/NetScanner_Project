import React, {useState, useEffect} from "react";
import './NetworkDetails.css'

function NetworkDetails(){
    useEffect(() => {
        const fetchNetworkState = async () => {
            const networkState = fetchData('http://localhost:5000/network_state', null);
        };
        fetchNetworkState();
    }, []);

    return (
        <div>
            <h1>Network Details:</h1>
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

export default NetworkDetails;