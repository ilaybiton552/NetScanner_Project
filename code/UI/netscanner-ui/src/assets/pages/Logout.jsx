import react, {useEffect} from "react"
import { useNavigate } from "react-router-dom";

function Logout({ setIsLogged }){
    const navigate = useNavigate();

    useEffect(() => {
        setIsLogged(false);
        fetchData('http://localhost:5000/stop_scan', null);
        navigate("/");
    })

    return (
        <div>
            <h1>Logout</h1>
        </div>
    )
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

export default Logout;