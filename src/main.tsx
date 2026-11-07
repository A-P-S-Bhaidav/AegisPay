import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

class ApplicationErrorBoundary extends React.Component<React.PropsWithChildren, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (this.state.failed) return (
      <main className="min-h-screen flex flex-col items-center justify-center gap-4 p-6 text-center">
        <h1 className="text-xl font-bold">AegisPay could not display this page</h1>
        <p className="text-sm text-slate-300">Reload to restore your workspace. Check the payment record before retrying a payment.</p>
        <button type="button" className="btn-cobalt px-4 py-2" onClick={() => window.location.reload()}>Reload workspace</button>
      </main>
    );
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ApplicationErrorBoundary><App /></ApplicationErrorBoundary>
  </React.StrictMode>
);
