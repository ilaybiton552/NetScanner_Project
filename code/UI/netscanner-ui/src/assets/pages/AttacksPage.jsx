import React, {useState, useEffect} from "react";
import './AttacksPage.css'

function AttacksPage(){
    const [attacks, setAttacks] = useState([]);
    const [wait, setWait] = useState(true);

    useEffect(() => {
        const fetchAttacks = async () => {
            const attacksList = await fetchData('http://localhost:5000/all_scan_results', null);
            setAttacks(attacksList)
            setWait(false)
        };
        fetchAttacks();
    }, []);

    return (
        <div className="center">
            <h1>Attacks Details:</h1>
            {wait ? (<p>Loading...</p>) : 
            (
                attacks.map((attack) => (
                    <div>
                        <ul>
                            <li>IP Address: {attack}</li>
                            <li>Mac Address: {attack}</li>
                            <li>Manufacture: {attack}</li>
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