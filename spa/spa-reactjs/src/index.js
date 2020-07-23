import React from "react";
import ReactDOM from "react-dom";
import "./index.css";
import App from "./App";
import { Auth0Provider } from "@auth0/auth0-react";

ReactDOM.render(
  <Auth0Provider
    domain="yufu-idp.i.yufuid.com/sso/tn-yufu/ai-e7ea09adfa74466c9530899358c733a1/oidc"
    clientId="ai-e7ea09adfa74466c9530899358c733a1"
    audience="http://127.0.0.1:8888/api/todos"
    scope="read:todos"
    redirectUri={window.location.origin}
    issuer="yufu-idp.i.yufuid.com"
  >
    <App />
  </Auth0Provider>,
  document.getElementById("root")
);
