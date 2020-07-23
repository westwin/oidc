import React, { useEffect, useState } from "react";
import { useAuth0 } from "@auth0/auth0-react";

const Todos = () => {
  const { getAccessTokenSilently } = useAuth0();
  const [todos, setTodos] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const token = await getAccessTokenSilently({});
        const response = await fetch("http://127.0.0.1:8888/api/todos", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        setTodos(await response.json());
      } catch (e) {
        console.error(e);
      }
    })();
  }, [getAccessTokenSilently]);

  if (!todos) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <p>below is your todos</p>
      <ul>
        {todos.map((todo, index) => {
          return (
            <li key={index}>
              {todo.name} on {todo.when}
            </li>
          );
        })}
      </ul>
    </div>
  );
};

export default Todos;
