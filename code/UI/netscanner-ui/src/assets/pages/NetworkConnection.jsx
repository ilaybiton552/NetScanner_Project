import React, {useState, useEffect} from "react";
import './NetworkConnection.css'

function NetworkConnection() {
    const [state, setState] = useState();
    const [ssid, setSSID] = useState();
    const [networks, setNetworks] = useState(() => fetchData('http://localhost:5000/networks', null));

    useEffect(() => {
        const fetchNetworkData = async () => {
            try {
                const networkData = await fetchData('http://localhost:5000/networks', null);
                setNetworks(networkData);
            } catch (error) {
                console.error('Error fetching networks:', error);
            }
        };

        if (networks instanceof Promise) {
            fetchNetworkData();
        }
    }, [networks]);

    const openPasswordInput = (ssid) => {
        setState(true);
        setSSID(ssid);
    };

    const connectToNetwork = () => {
        var password = document.getElementById("input").value;
        const network_info = { 'ssid': ssid, 'password': password};
        const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(network_info)};
        fetchData('http://localhost:5000/networks', options).then(data => document.getElementById("connectionStatus").textContent = data.Message || data.Error);
    }

    return (
        <div>
            <h1>List of Networks:</h1>
            <div className="center" >
                {state ?
                <div id="container">
                    <p>Enter Password:</p>
                    <input type="password" id="input"/> 
                    <button onClick={connectToNetwork}>Connect</button>
                    <p id="connectionStatus"></p>
                </div> : null}
                {Array.isArray(networks) ? (
                    networks.map((network, index) => (
                        <div key={index} id={network.ssid}>
                            <button className="networkDesign" onClick={() => openPasswordInput(network.ssid)}>
                                <ul>
                                    <li>Name: {network.ssid}</li>
                                    <li>Type: {network.network_type}</li>
                                    <li>Authentication: {network.authentication}</li>
                                    <li>Encryption: {network.encryption}</li>
                                </ul>
                            </button>
                            <br />
                        </div>
                    ))
                ) : (
                    <p>Loading...</p>
                )}
            </div>
        </div>
    );
}

async function fetchData(url, options) {
    try {
        let response = await fetch(url, options);
        const data = await response.json();
        console.log(data);
        return data;
    }
    catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
}

export default NetworkConnection