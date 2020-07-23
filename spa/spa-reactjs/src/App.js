import React from "react";
import "./App.css";
import Todos from "./Todos";
import { useAuth0 } from "@auth0/auth0-react";

function App() {
  const {
    isLoading,
    isAuthenticated,
    error,
    user,
    loginWithRedirect,
  } = useAuth0();

  if (isLoading) {
    return <div>Loading...</div>;
  }
  if (error) {
    return <div>Oops... {error.message}</div>;
  }

  if (isAuthenticated) {
    return (
      <div>
        <div>
          Hello {user.sub} {user.user_id}
        </div>
        <div>
          <Todos />
        </div>
      </div>
    );
  } else {
    return <button onClick={loginWithRedirect}>Log in</button>;
  }
}

export default App;
