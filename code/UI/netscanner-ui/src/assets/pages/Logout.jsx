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

export default Logout;