import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../theme";
import "../styles/tokens.css";
import "../styles/app.css";
import { Login, readInfo } from "./Login";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Login info={readInfo()} />
  </StrictMode>,
);
