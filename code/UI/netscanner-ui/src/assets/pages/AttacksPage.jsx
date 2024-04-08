import React, {useState, useEffect} from "react";
import './AttacksPage.css'

function AttacksPage({username}){
    const [attacks, setAttacks] = useState([]);
    const [wait, setWait] = useState(true);

    useEffect(() => {
        fetchAttacks();
    }, []);

    const fetchAttacks = async () => {
        const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({'username': username})};
        const attacksList = await fetchData('http://localhost:5000/scan_results', options);
        //const attacksList = await fetchData('http://localhost:5000/all_scan_results', null);
        setAttacks(attacksList);
        console.log(attacksList);
        setWait(false);
    };

    return (
        <div className="center">
            <h1>Attacks Details:</h1>
            <button className="refreshButton" onClick={fetchAttacks}>Refresh Data</button>
            <div className="center">
                {wait ? (<p>Loading...</p>) : 
                (
                    attacks.map((attack) => (
                        <div>
                            {attack.security_attack === "Evil Twin" ? (<ul className="ulStyle">
                                <li className="liStyle">Attack: {attack.security_attack}</li>
                                <li className="liStyle">Date: {attack.scan_date}</li>
                            </ul>) :(
                            <ul className="ulStyle">
                                <li className="liStyle">Attack: {attack.security_attack}</li>
                                <li className="liStyle">Attacker IP: {attack.ip_address}</li>
                                <li className="liStyle">Attacker Mac: {attack.mac_address}</li>
                                <li className="liStyle">Date: {attack.scan_date}</li>
                                <li className="liStyle">Network Name: {attack.ssid}</li>
                            </ul>
                                )}
                        </div>
                    ))
                ) }
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

export default AttacksPage;