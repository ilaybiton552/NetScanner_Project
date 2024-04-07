import react, {useEffect} from "react"
import { useHistory } from "react-router-dom";

function Logout(){
    const history = useHistory();

    useEffect(() => {
        setIsLogged(false);
        history.push("/");
    }, [history])

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
        console.log(response);
        return data;
    }
    catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
}

export default Logout;