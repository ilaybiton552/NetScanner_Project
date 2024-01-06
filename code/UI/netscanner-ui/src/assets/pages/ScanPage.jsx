import React, {useState} from "react";
import './ScanPage.css'

function ScanPage(){
    const [scan, setScan] = useState(true);
    const [attacks, setAttacks] = useState( {
        dns_poisoning: false,
        syn_flood: false,
        arp_spoofing: false,
        smurf: false,
        evil_twin: false
    });

    const handleCheckboxChange = (attackType) => {
        setAttacks((prevAttacks) => {
            const updatedAttacks = {...prevAttacks,
                [attackType]: !prevAttacks[attackType]
            };
            if (!scan) {
                const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(updatedAttacks)};
                fetchData('http://localhost:5000/update_scan', options).then(data => document.getElementById("scanningDetails").textContent = data.Message);
            }
            return updatedAttacks;
        });
    };

    const scanClick = () => {
        setScan(!scan);
        if (scan) {
            const options = {method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(attacks)};
            fetchData('http://localhost:5000/start_scan', options).then(data => document.getElementById("scanningDetails").textContent = data.Message || data.Error);
        }
        else {
            fetchData('http://localhost:5000/stop_scan', null).then(data => document.getElementById("scanningDetails").textContent = data.Message);
        }
    }

    return (
        <div className="mainDiv">
            <h1>List of Attacks:</h1>
            {Object.keys(attacks).map((attackType, index) => (
                <div key={index}>
                    <label>
                        <input
                            type="checkbox"
                            id={attackType}
                            checked={attacks[attackType]}
                            onChange={() => handleCheckboxChange(attackType)}
                        />
                        {attackType.replace(/_/g, ' ')}
                    </label>
                    <br />
                </div>
            ))}
            <br/>
            <button id="scanButton" onClick={scanClick}>{scan ? "Start Scanning": "Stop Scanning"}</button>
            <p id="scanningDetails"/>
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

export default ScanPage;