import react, {useEffect} from "react"

function Logout({ setIsLogged }){
    useEffect(() => {
        setIsLogged(false);
    })

    return (
        <div>
            <h1>Logout</h1>
        </div>
    )
}

export default Logout;