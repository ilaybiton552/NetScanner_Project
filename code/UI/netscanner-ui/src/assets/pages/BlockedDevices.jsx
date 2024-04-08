import React, {useState, useEffect} from "react";
import './NetworkDetails.css'

function BlockedDevices({username}){
    const [comps, setComps] = useState([]);
    const [wait, setWait] = useState(true);

    useEffect(() => {
        fetchBlockedComputers();
    }, []);

    const fetchBlockedComputers = async () => {
        const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({'username': username})};
        const compsData = await fetchData('http://localhost:5000/get_blocked_comps', options);
        setComps(compsData);
        setWait(false);
    };

    const UnblockUser = async (ip, mac) => {
        const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({'username': username, 'ip_address': ip, "mac_address": mac})};
        const ans = await fetchData('http://localhost:5000/unblock_comp', options);
        alert(ans.Message);
        fetchBlockedComputers();
    };

    return (
        <div className="center">
            <h1>Blocked Devices:</h1>
            <div className="center">
                {wait ? (<p>Loading...</p>) : 
                (
                    comps.map((comp) => (
                        <div>
                            <button className="but" onClick={() => UnblockUser(comp.ip_address, comp.mac_address)}>
                                <ul className="ulStyle">
                                    <li className="liStyle">IP Address: {comp.ip_address}</li>
                                    <li className="liStyle">Mac Address: {comp.mac_address}</li>
                                    <li className="liStyle">Attack: {comp.attack}</li>
                                </ul>
                            </button>
                        </div>
                    ))
                ) }
                <button className="refreshButton" onClick={fetchBlockedComputers}>Refresh Data</button>
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

export default BlockedDevices;