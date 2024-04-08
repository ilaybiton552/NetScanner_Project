import React, {useState, useEffect} from "react";
import './NetworkDetails.css'

function NetworkDetails(){
    const [devices, setDevices] = useState([]);
    const [wait, setWait] = useState(true);

    useEffect(() => {
        fetchNetworkState();
    }, []);

    const fetchNetworkState = async () => {
        const networkState = await fetchData('http://localhost:5000/network_state', null);
        setDevices(networkState)
        setWait(false)
    };

    return (
        <div className="center">
            <h1>Network Details:</h1>
            <div className="center">
                {wait ? (<p>Loading...</p>) : 
                (
                    devices.map((device) => (
                        <div>
                            <ul className="ulStyle">
                                <li className="liStyle">IP Address: {device.ip}</li>
                                <li className="liStyle">Mac Address: {device.mac}</li>
                                <li className="liStyle">Manufacture: {device.manufacturer}</li>
                            </ul>
                        </div>
                    ))
                ) }
                <button className="refreshButton" onClick={fetchNetworkState}>Refresh Data</button>
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

export default NetworkDetails;