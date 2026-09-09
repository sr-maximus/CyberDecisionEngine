import { AlertTriangle, RotateCcw } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";

interface AppErrorBoundaryProps {
  children: ReactNode;
}

interface AppErrorBoundaryState {
  hasError: boolean;
}

export class AppErrorBoundary extends Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("CyberDecisionEngine UI error", error, info.componentStack);
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    const isSpanish = !navigator.language.toLowerCase().startsWith("en");
    return (
      <main className="app-recovery" role="alert">
        <section>
          <div className="app-recovery-icon" aria-hidden="true">
            <AlertTriangle size={26} />
          </div>
          <div>
            <h1>{isSpanish ? "No fue posible mostrar esta vista" : "This view could not be displayed"}</h1>
            <p>
              {isSpanish
                ? "La ejecución del análisis continúa en el backend. Recarga la interfaz para recuperar la vista sin iniciar otra corrida."
                : "The analysis continues in the backend. Reload the interface to recover the view without starting another run."}
            </p>
          </div>
          <button className="primary-button" onClick={() => window.location.reload()} type="button">
            <RotateCcw size={18} />
            {isSpanish ? "Recargar interfaz" : "Reload interface"}
          </button>
        </section>
      </main>
    );
  }
}
