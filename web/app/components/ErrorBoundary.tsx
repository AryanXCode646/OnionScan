"use client";

import React, { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught component error:", error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            padding: "32px",
            borderRadius: "8px",
            border: "1px solid #ef4444",
            backgroundColor: "#090d16",
            textAlign: "center",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: "300px",
          }}
        >
          <AlertTriangle size={48} style={{ color: "#ef4444", marginBottom: "12px" }} />
          <h4 style={{ color: "#f8fafc", fontSize: "1.125rem", fontWeight: 600, margin: "0 0 8px 0" }}>
            {this.props.fallbackTitle || "Component Encountered an Unexpected Error"}
          </h4>
          <p style={{ color: "var(--text-muted)", fontSize: "0.875rem", maxWidth: "500px", margin: "0 0 16px 0" }}>
            {this.state.error?.message || "An unhandled runtime error occurred during rendering."}
          </p>
          <button
            onClick={this.handleReset}
            className="btn btn-secondary"
            style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
          >
            <RotateCcw size={14} /> Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
