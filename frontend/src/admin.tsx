import React from "react";
import ReactDOM from "react-dom/client";
import { AppProviders } from "./shared/components/layout/AppProviders";
import { AdminApp } from "./admin/AdminApp";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("admin-root") as HTMLElement).render(
  <React.StrictMode>
    <AppProviders>
      <AdminApp />
    </AppProviders>
  </React.StrictMode>,
);
