import react, {useEffect} from "react"
import { useNavigate } from "react-router-dom";

function Logout({ setIsLogged }){
    const navigate = useNavigate();

    useEffect(() => {
        setIsLogged(false);
        navigate("/")
    })

    return (
        <div>
            <h1>Logout</h1>
        </div>
    )
}

export default Logout;