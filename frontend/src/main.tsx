import React from "react";
import ReactDOM from "react-dom/client";
import { AppProviders } from "./shared/components/layout/AppProviders";
import { UserApp } from "./user/UserApp";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AppProviders>
      <UserApp />
    </AppProviders>
  </React.StrictMode>,
);
