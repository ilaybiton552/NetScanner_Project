import React, {useState, useEffect} from "react";
import './AttacksPage.css'

function AttacksPage(){
    const [wait, setWait] = useState(true);

    useEffect(() => {
        const fetchNetworkState = async () => {
            const networkState = await fetchData('http://localhost:5000/network_state', null);
            setDevices(networkState)
            setWait(false)
        };
        fetchNetworkState();
    }, []);

    return (
        <div>
            <h1>Attacks Details:</h1>
            {wait ? (<p>Loading...</p>) : 
            (
                devices.map((device) => (
                    <div>
                        <ul>
                            <li>IP Address: {device.ip}</li>
                            <li>Mac Address: {device.mac}</li>
                            <li>Manufacture: {device.manufacturer}</li>
                        </ul>
                    </div>
                ))
            ) }
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

export default AttacksPage;